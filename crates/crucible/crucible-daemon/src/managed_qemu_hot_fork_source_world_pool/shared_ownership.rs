//! Keeps actual shared Source return custody outside the allocation it protects.
//!
//! Borrowed leases hold only the original allocation. The managed owner or an
//! exclusive lease retains the original Main pair. Unissued sharing exists only
//! in component tests and never supplies native return evidence.

use super::*;
use crate::vm_lifecycle::{MainSharedSource, PreparedSharedSource};

pub(super) enum SharedSourceOwnership {
    Main(MainSharedSource),
    Prepared(PreparedSharedSource),
    #[cfg(test)]
    Component(ComponentSharedSource),
}

impl SharedSourceOwnership {
    pub(super) fn prepare(
        source: ProductionVmHotForkSourceWorld,
    ) -> Result<Self, ProductionVmHotForkSourceWorld> {
        let prepared = match source.into_shared_return_parts() {
            Ok(prepared) => prepared,
            Err(source) => {
                #[cfg(test)]
                if crate::vm_lifecycle::unissued_component_source(&source) {
                    return Ok(Self::Component(ComponentSharedSource {
                        source: Arc::new(Mutex::new(source)),
                        #[cfg(feature = "private-measurement-domain")]
                        parent_park: None,
                    }));
                }
                return Err(source);
            }
        };
        Ok(match prepared.into_shared() {
            Ok(shared) => Self::Main(shared),
            // Keep the SAME prepared Source and pair even on a constructor
            // refusal. No unit diagnostic may destroy this owner.
            Err(prepared) => Self::Prepared(prepared),
        })
    }

    pub(super) fn owner_ref(&self) -> Option<&Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        match self {
            Self::Main(source) => source.source_owner_ref(),
            Self::Prepared(_) => None,
            #[cfg(test)]
            Self::Component(source) => Some(&source.source),
        }
    }

    pub(super) fn with_unique<R>(
        &mut self,
        apply: impl FnOnce(&mut ProductionVmHotForkSourceWorld) -> R,
    ) -> Option<R> {
        match self {
            Self::Main(source) => source.with_unique_source(apply).ok(),
            Self::Prepared(_) => None,
            #[cfg(test)]
            Self::Component(source) => {
                crate::vm_lifecycle::with_unique_component_source(&mut source.source, apply).ok()
            }
        }
    }

    #[cfg(feature = "private-measurement-domain")]
    pub(super) fn adopt_parent_park(
        &mut self,
        gate: ManagedParentParkGate,
    ) -> Result<(), ManagedParentParkGate> {
        match self {
            Self::Main(source) => source.adopt_parent_park(gate),
            Self::Prepared(_) => Err(gate),
            #[cfg(test)]
            Self::Component(source) => {
                if source.parent_park.is_some() || !gate.matches_component_owner(&source.source) {
                    return Err(gate);
                }
                source.parent_park = Some(gate);
                Ok(())
            }
        }
    }

    pub(super) fn into_unique(self) -> Result<ProductionVmHotForkSourceWorld, Self> {
        match self {
            Self::Main(source) => source.into_unique_source().map_err(Self::Main),
            Self::Prepared(prepared) => Err(Self::Prepared(prepared)),
            #[cfg(test)]
            Self::Component(source) => source.into_unique().map_err(Self::Component),
        }
    }
}

pub(super) enum LeaseSource {
    Borrowed(Arc<Mutex<ProductionVmHotForkSourceWorld>>),
    Exclusive(SharedSourceOwnership),
}

impl LeaseSource {
    pub(super) fn owner_ref(&self) -> Option<&Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        match self {
            Self::Borrowed(source) => Some(source),
            Self::Exclusive(source) => source.owner_ref(),
        }
    }
}

#[cfg(test)]
pub(super) struct ComponentSharedSource {
    source: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    #[cfg(feature = "private-measurement-domain")]
    parent_park: Option<ManagedParentParkGate>,
}

#[cfg(test)]
impl ComponentSharedSource {
    fn into_unique(self) -> Result<ProductionVmHotForkSourceWorld, Self> {
        #[cfg(feature = "private-measurement-domain")]
        if self.parent_park.is_some() {
            // A negative operation-only Park fixture supplies no Main closure.
            return Err(self);
        }
        match crate::vm_lifecycle::take_unissued_component_source(self.source) {
            Ok(source) => Ok(source),
            Err(source) => Err(Self {
                source,
                #[cfg(feature = "private-measurement-domain")]
                parent_park: self.parent_park,
            }),
        }
    }
}
