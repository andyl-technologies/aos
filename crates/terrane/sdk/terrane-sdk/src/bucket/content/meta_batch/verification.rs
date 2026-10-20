//! Reuses only pure container parsing during one final metadata confirmation.
//!
//! Each member still freshly reads pack then index, checks both artifact hashes,
//! resolves its exact selected Live row and validates its schema, body identity,
//! length and offered bytes. No read observation or member-validation result is
//! retained. One owned slot bounds memory to one prior container's bytes/records
//! alongside the current freshly read pair; no reader borrows retained storage.

use super::super::{VerifiedBody, corrupt};
use crate::bucket::catalog::{Catalog, CatalogReads};
use crate::bucket::containers::parse_verified_container;
use crate::bucket::{BucketBinding, FileBucket};
use crate::pack::{IndexEntry, PackClass, PackHeader};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::bucket::PackInventoryEntry;
use terrane_format::identity::Identity;

struct Parsed {
    inventory: PackInventoryEntry,
    pack: Vec<u8>,
    index: Vec<u8>,
    header: PackHeader,
    entries: Vec<IndexEntry>,
}

/// Borrows the exact immutable selected catalog for one final confirmation loop.
///
/// The live borrow binds profile, generation, full inventory, merged locations,
/// quarantine and retirement geometry. Pointer comparison only rejects foreign
/// catalogs within that borrow; it never establishes freshness or authority.
pub(in crate::bucket::content) struct Confirmation<'catalog> {
    catalog: &'catalog Catalog,
    last: Option<Parsed>,
    #[cfg(all(test, feature = "tokio", unix))]
    enabled: bool,
    #[cfg(all(test, feature = "tokio", unix))]
    parses: usize,
}

impl<'catalog> Confirmation<'catalog> {
    /// Starts an empty preparation slot bound to one immutable final catalog.
    pub(in crate::bucket::content) fn new(catalog: &'catalog Catalog) -> Self {
        Self {
            catalog,
            last: None,
            #[cfg(all(test, feature = "tokio", unix))]
            enabled: true,
            #[cfg(all(test, feature = "tokio", unix))]
            parses: 0,
        }
    }

    /// Confirms one actual offered member, clearing preparation on any failure.
    ///
    /// # Errors
    /// Preserves ordinary physical, placement, schema and identity failures and
    /// rejects bytes differing from this member's exact offer.
    pub(in crate::bucket::content) async fn confirm_member<F, C, V, R>(
        &mut self,
        bucket: &FileBucket<F, C, V>,
        catalog: &Catalog,
        identity: &Identity,
        offered: &[u8],
        reads: &R,
    ) -> Result<(), StoreFailure>
    where
        F: LocalFs + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
        R: CatalogReads + ?Sized,
    {
        let result = match bucket
            .verified_body_with_confirmation(catalog, identity, reads, Some(&mut *self))
            .await
        {
            Ok(VerifiedBody::Bytes(bytes)) if bytes == offered => Ok(()),
            Ok(VerifiedBody::Bytes(_)) => Err(corrupt(identity)),
            Ok(VerifiedBody::ExcludedDetachedIndex) => {
                Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
            }
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.last = None;
        }
        result
    }

    /// Selects parsed metadata after the caller's fresh ordered reads and hashes.
    ///
    /// # Errors
    /// Preserves complete container-format failures and refuses missing members.
    pub(in crate::bucket::content) fn member(
        &mut self,
        catalog: &Catalog,
        inventory: &PackInventoryEntry,
        pack: &[u8],
        index: &[u8],
        identity: &Identity,
    ) -> Result<IndexEntry, StoreFailure> {
        let eligible = std::ptr::eq(self.catalog, catalog);
        #[cfg(all(test, feature = "tokio", unix))]
        let eligible = eligible && self.enabled;

        if eligible
            && let Some(last) = &self.last
            && last.inventory == *inventory
            && last.pack == pack
            && last.index == index
            && last.header.class() == PackClass::Meta
        {
            return find_member(&last.entries, identity);
        }

        // Drop the prior slot before cloning a replacement, so peak artifact
        // storage is one cached pair alongside this member's fresh pair.
        self.last = None;

        // Count the real parser call, including rejected attempts; no predicted
        // hit/miss counter substitutes for executed work in the regression.
        #[cfg(all(test, feature = "tokio", unix))]
        {
            self.parses += 1;
        }
        let reader = parse_verified_container(inventory, pack, index)?;
        let member = find_member(reader.entries(), identity)?;
        self.last = if eligible && reader.header().class() == PackClass::Meta {
            Some(Parsed {
                inventory: inventory.clone(),
                pack: pack.to_vec(),
                index: index.to_vec(),
                header: reader.header(),
                entries: reader.entries().to_vec(),
            })
        } else {
            None
        };
        Ok(member)
    }

    #[cfg(all(test, feature = "tokio", unix))]
    /// Starts the same confirmation path with successful parsing reuse disabled.
    pub(super) fn without_reuse(catalog: &'catalog Catalog) -> Self {
        let mut confirmation = Self::new(catalog);
        confirmation.enabled = false;
        confirmation
    }

    #[cfg(all(test, feature = "tokio", unix))]
    /// Returns actual calls to the complete pure container parser.
    pub(super) fn parses(&self) -> usize {
        self.parses
    }
}

fn find_member(entries: &[IndexEntry], identity: &Identity) -> Result<IndexEntry, StoreFailure> {
    // Complete parsing proves PACK-3 order before these owned records exist.
    let position = entries
        .binary_search_by(|entry| entry.hash().as_slice().cmp(identity.digest()))
        .map_err(|_| corrupt(identity))?;
    Ok(entries[position].clone())
}
