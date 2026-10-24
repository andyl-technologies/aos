//! Immutable baked-map storage and its actual enclosing allocation payment.
//!
//! Map values move their existing snapshot/profile Arcs. Keys are fixed hashes;
//! no nested map, node name, snapshot or launch-profile allocation is copied.

use super::*;
use crucible_engine::owned_decode::{DecodeBudget, DecodeCustody};
use crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose;

#[derive(Clone)]
pub(crate) enum CatalogPayment {
    Main {
        _purpose: AuthenticatedNativePoolPurpose,
    },
    Decode {
        _custody: DecodeCustody,
    },
}

pub(super) struct PaidBakedCatalog<T> {
    pub(super) entries: Arc<BTreeMap<(ContentHash, ContentHash), T>>,
    // The last wrapper destroys entries AND the Arc allocation before payment.
    // No Weak or independent owning map alias leaves this private wrapper.
    _payment: CatalogPayment,
}

impl<T> Clone for PaidBakedCatalog<T> {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            _payment: self._payment.clone(),
        }
    }
}

impl<T> PaidBakedCatalog<T> {
    pub(super) fn control_bytes(
        count: usize,
    ) -> Result<u64, ProductionBakedGenesisReplayCatalogError> {
        if count == 0 {
            return Err(ProductionBakedGenesisReplayCatalogError::Empty);
        }
        let (layout, _) = std::alloc::Layout::new::<(usize, usize)>()
            .extend(std::alloc::Layout::new::<
                BTreeMap<(ContentHash, ContentHash), T>,
            >())
            .map_err(|_| ProductionBakedGenesisReplayCatalogError::Geometry)?;
        let entries = DecodeBudget::btree_control_bytes::<(ContentHash, ContentHash), T>(count)?;
        entries
            .checked_add(layout.pad_to_align().size() as u64)
            .ok_or(ProductionBakedGenesisReplayCatalogError::Geometry)
    }

    pub(super) fn new_under_original(
        entries: impl IntoIterator<Item = ((ContentHash, ContentHash), T)>,
        original: &DecodeBudget,
    ) -> Result<Self, ProductionBakedGenesisReplayCatalogError> {
        let entries = entries.into_iter();
        let (count, upper) = entries.size_hint();
        if upper != Some(count) {
            return Err(ProductionBakedGenesisReplayCatalogError::Geometry);
        }
        original.charge_bytes(Self::control_bytes(count)?)?;
        Self::new_prepaid(
            entries,
            count,
            CatalogPayment::Decode {
                _custody: original.custody(),
            },
        )
    }

    pub(super) fn new_prepaid(
        entries: impl IntoIterator<Item = ((ContentHash, ContentHash), T)>,
        count: usize,
        payment: CatalogPayment,
    ) -> Result<Self, ProductionBakedGenesisReplayCatalogError> {
        if count == 0 {
            return Err(ProductionBakedGenesisReplayCatalogError::Empty);
        }
        let mut retained = BTreeMap::new();
        let mut seen = 0usize;
        for (basis, checkpoint) in entries {
            // Even an untrusted iterator cannot insert beyond prepaid geometry.
            if seen == count {
                return Err(ProductionBakedGenesisReplayCatalogError::Geometry);
            }
            seen += 1;
            if retained.insert(basis, checkpoint).is_some() {
                return Err(ProductionBakedGenesisReplayCatalogError::DuplicateBasis);
            }
        }
        if seen != count {
            return Err(ProductionBakedGenesisReplayCatalogError::Geometry);
        }
        Ok(Self {
            entries: Arc::new(retained),
            _payment: payment,
        })
    }
}

#[cfg(test)]
mod tests;
