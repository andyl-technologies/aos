//! Keeps the original Main return pair outside a shared Source allocation.
//!
//! Preparation extracts the existing carrier and destination before the one
//! admitted Arc allocation. Return publishes that same Arc in that same carrier.
//! Exclusive allocation access permits moving the body out and destroying the
//! empty Arc; actual native return still uses ordinary Source retirement.

use super::*;
use crate::lifecycle_cleanup::{PreparedSourceSelector, SourceBodyReturn};
use std::fmt;

type CleanupError = crate::ProductionVmConstructionCleanupError;

/// Owns a genuine Source and its original pair before shared allocation birth.
#[must_use = "the actual Source and its original return pair must stay together"]
pub(crate) struct PreparedSharedSource {
    state: PreparedState,
}

enum PreparedState {
    Live {
        source: ProductionVmHotForkSourceWorld,
        carrier: Box<ProductionVmConstructionCustody>,
        destination: SourceBodyReturn,
        selector: PreparedSourceSelector,
    },
    Returned,
}

/// Retains the original return pair outside the one existing shared allocation.
///
/// Its destructor publishes custody without native cleanup or allocation. All
/// shared aliases must actually end before Main can destroy that allocation.
#[must_use = "the shared Source must return through its original Main role"]
pub(crate) struct MainSharedSource {
    state: SharedState,
}

enum SharedState {
    Live {
        source: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        carrier: Box<ProductionVmConstructionCustody>,
        destination: SourceBodyReturn,
        selector: PreparedSourceSelector,
        parent_park: ParentParkCustody,
    },
    Returned,
}

impl ProductionVmHotForkSourceWorld {
    /// Extracts the same genuine return pair before the shared allocation exists.
    ///
    /// # Errors
    /// Returns this same Source unless its genuine pair, pristine carrier and
    /// original launcher selection agree. An unissued component is refused.
    pub(crate) fn into_shared_return_parts(mut self) -> Result<PreparedSharedSource, Self> {
        if self.retirement.is_some() {
            return Err(self);
        }
        let Some(lifecycle) = self.lifecycle.as_mut() else {
            return Err(self);
        };
        let Some(selector) = lifecycle.prepared_source_selector() else {
            return Err(self);
        };
        let (carrier, destination) = match lifecycle.take_retirement_custody() {
            Ok(parts) => parts,
            Err(_) => return Err(self),
        };
        let Some(destination) = destination else {
            lifecycle.restore_retirement_custody(carrier, None);
            return Err(self);
        };
        if !destination.matches_selector(&selector) {
            lifecycle.restore_retirement_custody(carrier, Some(destination));
            return Err(self);
        }
        Ok(PreparedSharedSource {
            state: PreparedState::Live {
                source: self,
                carrier,
                destination,
                selector,
            },
        })
    }

    /// Moves all fields, leaving an inert Source in an exclusively owned Arc.
    ///
    /// The caller has validated the detached original pair. This move performs
    /// no callbacks or destruction; dropping the remaining empty value cannot
    /// run Source cleanup. New owning Source fields must join this exact move.
    fn take_shared_body(&mut self) -> Self {
        Self {
            lifecycle: self.lifecycle.take(),
            continuation: self.continuation.take(),
            prepared: std::mem::take(&mut self.prepared),
            disk_custody: std::mem::take(&mut self.disk_custody),
            cleanup_observer: self.cleanup_observer.take(),
            retirement: self.retirement.take(),
            target_backends_lent: std::mem::take(&mut self.target_backends_lent),
            #[cfg(feature = "private-measurement-domain")]
            managed_parent_park_history: self.managed_parent_park_history.take(),
        }
    }

    fn matches_shared_selection(&self, selector: &PreparedSourceSelector) -> bool {
        self.retirement.is_none()
            && self.lifecycle.as_ref().is_some_and(|lifecycle| {
                matches!(
                    lifecycle.construction_custody,
                    LifecycleConstructionCustody::Unissued(None)
                ) && lifecycle
                    .prepared_source_selector()
                    .as_ref()
                    .is_some_and(|actual| actual.same_role(selector))
            })
    }
}

impl PreparedSharedSource {
    /// Creates the one already-admitted shared Source allocation.
    ///
    /// The original Source query must include this actual Arc/Mutex body and
    /// header before this method runs. This method supplies no funding itself.
    ///
    /// # Errors
    /// Returns this same preparation if its private state was already consumed.
    pub(crate) fn into_shared(mut self) -> Result<MainSharedSource, Self> {
        match std::mem::replace(&mut self.state, PreparedState::Returned) {
            PreparedState::Live {
                source,
                carrier,
                destination,
                selector,
            } => Ok(MainSharedSource {
                state: SharedState::Live {
                    source: Arc::new(Mutex::new(source)),
                    carrier,
                    destination,
                    selector,
                    parent_park: ParentParkCustody::default(),
                },
            }),
            PreparedState::Returned => Err(self),
        }
    }
}

impl Drop for PreparedSharedSource {
    fn drop(&mut self) {
        if let PreparedState::Live {
            source,
            carrier,
            destination,
            selector: _,
        } = std::mem::replace(&mut self.state, PreparedState::Returned)
        {
            drop(destination.deliver(carrier.install_owned_source(source)));
        }
    }
}

impl MainSharedSource {
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn adopt_parent_park(
        &mut self,
        gate: crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkGate,
    ) -> Result<(), crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkGate> {
        let SharedState::Live {
            selector,
            parent_park,
            ..
        } = &mut self.state
        else {
            return Err(gate);
        };
        if !gate.matches_selection(selector) || parent_park.gate.is_some() {
            return Err(gate);
        }
        parent_park.gate = Some(gate);
        Ok(())
    }

    /// Borrows the existing allocation for identity comparisons without cloning it.
    pub(crate) fn source_owner_ref(&self) -> Option<&Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        match &self.state {
            SharedState::Live { source, .. } => Some(source),
            SharedState::Returned => None,
        }
    }

    /// Borrows a uniquely owned, unpoisoned Source before an owning extraction.
    ///
    /// # Errors
    /// Retains the actual allocation and pair on aliases, poison or selection
    /// mismatch. The scoped operation supplies no native return proof.
    pub(crate) fn with_unique_source<R>(
        &mut self,
        apply: impl FnOnce(&mut ProductionVmHotForkSourceWorld) -> R,
    ) -> Result<R, CleanupError> {
        let SharedState::Live {
            source, selector, ..
        } = &mut self.state
        else {
            return Err(CleanupError::Retained("shared Source was already returned"));
        };
        let body = unique_shared_body(source)?;
        if !body.matches_shared_selection(selector) {
            return Err(CleanupError::Retained("shared Source selection changed"));
        }
        Ok(apply(body))
    }

    /// Returns the same Source only after actual shared-allocation exclusion.
    ///
    /// Exclusion proves memory ownership alone. This operation performs no
    /// native cleanup and restores the same genuine return pair to the Source.
    ///
    /// # Errors
    /// Preserves this same Arc and pair on any strong/weak alias, mutex poison,
    /// foreign Source selection or unavailable lifecycle. No Arc is rebuilt.
    pub(crate) fn into_unique_source(mut self) -> Result<ProductionVmHotForkSourceWorld, Self> {
        let SharedState::Live {
            mut source,
            carrier,
            destination,
            selector,
            mut parent_park,
        } = std::mem::replace(&mut self.state, SharedState::Returned)
        else {
            return Err(self);
        };
        let restore = |source, carrier, destination, selector, parent_park| SharedState::Live {
            source,
            carrier,
            destination,
            selector,
            parent_park,
        };
        let body = match unique_shared_body(&mut source) {
            Ok(body) if body.matches_shared_selection(&selector) => body,
            _ => {
                self.state = restore(source, carrier, destination, selector, parent_park);
                return Err(self);
            }
        };
        if !parent_park.transfer_to(body) {
            self.state = restore(source, carrier, destination, selector, parent_park);
            return Err(self);
        }
        let Some(lifecycle) = body.lifecycle.as_mut() else {
            self.state = restore(source, carrier, destination, selector, parent_park);
            return Err(self);
        };
        lifecycle.construction_custody = LifecycleConstructionCustody::Main {
            carrier,
            destination,
        };
        let owned = body.take_shared_body();
        // The allocation contains only inert fields now. Its destruction ends
        // before the actual Source leaves this method; no poison reconstruction
        // or temporarily detached owning body is needed.
        drop(source);
        Ok(owned)
    }

    /// Publishes the same allocation without waiting for a Source mutex.
    pub(crate) fn return_to_main(&mut self) {
        if let SharedState::Live {
            source,
            carrier,
            destination,
            selector,
            parent_park,
        } = std::mem::replace(&mut self.state, SharedState::Returned)
        {
            drop(destination.deliver(carrier.install_owned_shared_source(
                source,
                selector,
                parent_park,
            )));
        }
    }
}

impl Drop for MainSharedSource {
    fn drop(&mut self) {
        self.return_to_main();
    }
}

impl fmt::Debug for PreparedSharedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSharedSource")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for MainSharedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MainSharedSource")
            .finish_non_exhaustive()
    }
}

/// Keeps the actual allocation until its body can leave without a shared alias.
///
/// Neither empty option is a closure proof. `source` becomes populated before
/// the emptied allocation is destroyed, and only that actual body drives native
/// cleanup. This phase contains no strong edge back to the Main queue.
pub(in crate::vm_lifecycle) struct SharedSourceBody {
    shared: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    source: Option<ProductionVmHotForkSourceWorld>,
    selector: PreparedSourceSelector,
    parent_park: ParentParkCustody,
}

impl SharedSourceBody {
    pub(in crate::vm_lifecycle) fn new(
        source: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        selector: PreparedSourceSelector,
        parent_park: ParentParkCustody,
    ) -> Self {
        Self {
            shared: Some(source),
            source: None,
            selector,
            parent_park,
        }
    }

    pub(in crate::vm_lifecycle) fn retry_body(&mut self) -> Result<(), CleanupError> {
        if self.source.is_none() {
            let shared = self.shared.as_mut().ok_or(CleanupError::Retained(
                "shared Source allocation and body are both unavailable",
            ))?;
            if !self.parent_park.retry(shared) {
                return Err(CleanupError::Retained(
                    "same actual managed Park remains retained",
                ));
            }
            let body = unique_shared_body(shared)?;
            if !body.matches_shared_selection(&self.selector) {
                return Err(CleanupError::Retained(
                    "shared Source does not retain its original detached selection",
                ));
            }
            if !self.parent_park.transfer_to(body) {
                return Err(CleanupError::Retained(
                    "same Source retains independent managed Park history",
                ));
            }
            self.source = Some(body.take_shared_body());
            // The actual Source is already retained in this same Main carrier.
            // Only the inert allocation dies here, before native cleanup begins.
            drop(self.shared.take());
        }
        self.source
            .as_mut()
            .ok_or(CleanupError::Retained("shared Source body is unavailable"))?
            .retry_source_retirement_body()
    }

    pub(in crate::vm_lifecycle) fn take_post_body(
        &mut self,
    ) -> Result<Option<crate::ProductionVmConstructionPostBody>, CleanupError> {
        if self.shared.is_some() {
            return Err(CleanupError::Retained(
                "shared Source allocation is still live",
            ));
        }
        self.source
            .as_mut()
            .ok_or(CleanupError::Retained("shared Source body is unavailable"))?
            .take_source_retirement_post_body()
    }
}

/// Obtains allocation exclusion without locking, consuming, or rebuilding it.
fn unique_shared_body<T>(shared: &mut Arc<Mutex<T>>) -> Result<&mut T, CleanupError> {
    Arc::get_mut(shared)
        .ok_or(CleanupError::SharedAliasesPending)?
        .get_mut()
        .map_err(|_| CleanupError::Poisoned)
}

#[cfg(test)]
mod tests;

/// Refuses genuine Main custody in the operation-only unissued component path.
#[cfg(test)]
pub(crate) fn unissued_component_source(source: &ProductionVmHotForkSourceWorld) -> bool {
    source.lifecycle.as_ref().is_some_and(|lifecycle| {
        matches!(
            lifecycle.construction_custody,
            LifecycleConstructionCustody::Unissued(_)
        )
    })
}

/// Moves the same unissued fixture body after actual allocation exclusion.
#[cfg(test)]
pub(crate) fn take_unissued_component_source(
    mut shared: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
) -> Result<ProductionVmHotForkSourceWorld, Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
    let source = match unique_shared_body(&mut shared) {
        Ok(source) if unissued_component_source(source) => source.take_shared_body(),
        _ => return Err(shared),
    };
    drop(shared);
    Ok(source)
}

#[cfg(test)]
pub(crate) fn with_unique_component_source<R>(
    shared: &mut Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    apply: impl FnOnce(&mut ProductionVmHotForkSourceWorld) -> R,
) -> Result<R, CleanupError> {
    let source = unique_shared_body(shared)?;
    if !unissued_component_source(source) {
        return Err(CleanupError::Retained(
            "component Source carries genuine Main custody",
        ));
    }
    Ok(apply(source))
}

/// Keeps the actual paid Park record outside the Source allocation.
#[derive(Default)]
pub(in crate::vm_lifecycle) struct ParentParkCustody {
    #[cfg(feature = "private-measurement-domain")]
    gate: Option<crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkGate>,
}

impl ParentParkCustody {
    fn retry(&self, source: &Arc<Mutex<ProductionVmHotForkSourceWorld>>) -> bool {
        #[cfg(feature = "private-measurement-domain")]
        if let Some(gate) = &self.gate {
            return gate.retry_retirement(source);
        }
        let _ = source;
        true
    }

    fn transfer_to(&mut self, source: &mut ProductionVmHotForkSourceWorld) -> bool {
        #[cfg(feature = "private-measurement-domain")]
        if let Some(gate) = &self.gate {
            if !gate.is_physically_returned() || source.managed_parent_park_history.is_some() {
                return false;
            }
            source.managed_parent_park_history = self.gate.take();
        }
        let _ = source;
        true
    }
}
