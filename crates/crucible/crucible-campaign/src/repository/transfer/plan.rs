//! Replay of an archive plan's spooled inventories and metadata.
//!
//! A plan keeps its canonical page envelopes in private scratch storage. These
//! visitors replay them one page at a time, binding every page to the
//! manifest's page IDs, so callers see exactly the inventory the manifest
//! digests describe without the plan holding it in memory.

use super::inventory::{InventoryCursor, SpooledPages};
use super::*;

impl CampaignArchivePlan {
    /// Replays the selected inventory in ascending identity order.
    ///
    /// Entries come from the plan's spooled pages, one page at a time.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a [`CampaignRepositoryError`]
    /// when the spool cannot be read or no longer matches the manifest.
    pub fn visit_selected<E>(
        &self,
        visit: impl FnMut(ArchiveObjectEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        self.visit_inventory(ArchiveInventoryDisposition::Selected, visit)
    }

    /// Replays the explicitly omitted inventory in ascending identity order.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a [`CampaignRepositoryError`]
    /// when the spool cannot be read or no longer matches the manifest.
    pub fn visit_omitted<E>(
        &self,
        visit: impl FnMut(ArchiveObjectEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        self.visit_inventory(ArchiveInventoryDisposition::Omitted, visit)
    }

    /// Visits every object protected while this plan is being transferred.
    ///
    /// Selected objects come first in ascending order, then the canonical
    /// inventory pages in manifest order, then the manifest. Each visit
    /// carries the object's logical length.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a [`CampaignRepositoryError`]
    /// when the spool cannot be read or no longer matches the manifest.
    pub fn visit_transfer_objects<E>(
        &self,
        mut visit: impl FnMut(ContentId, u64) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        self.visit_selected(|entry| visit(entry.id(), entry.logical_length()))?;
        self.visit_page_envelopes(|envelope| {
            let length = envelope.canonical_bytes().len() as u64;
            visit(envelope.content_id(), length)
        })?;
        let manifest_length = self.manifest_envelope.canonical_bytes().len() as u64;
        visit(self.manifest_id.content_id(), manifest_length)
    }

    /// Collects every transfer-protected object, sorted and duplicate free.
    ///
    /// This materializes [`Self::visit_transfer_objects`] for callers whose
    /// own records already bound the inventory, such as a transfer journal.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the spool cannot be read or no
    /// longer matches the manifest.
    pub fn transfer_objects(&self) -> Result<Vec<(ContentId, u64)>, CampaignRepositoryError> {
        let mut objects = BTreeSet::new();
        self.visit_transfer_objects(|id, length| {
            objects.insert((id, length));
            Ok::<(), CampaignRepositoryError>(())
        })?;
        Ok(objects.into_iter().collect())
    }

    fn visit_inventory<E>(
        &self,
        disposition: ArchiveInventoryDisposition,
        mut visit: impl FnMut(ArchiveObjectEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        let (file, pages) = match disposition {
            ArchiveInventoryDisposition::Selected => {
                (&self.selected_pages, self.manifest.selected_pages())
            }
            ArchiveInventoryDisposition::Omitted => {
                (&self.omitted_pages, self.manifest.omitted_pages())
            }
        };
        let mut cursor = InventoryCursor::spool(file, pages, disposition)?;
        while let Some(entry) = cursor.next_entry()? {
            visit(entry)?;
        }
        Ok(())
    }

    /// Visits every spooled page envelope, selected pages first, in manifest order.
    pub(super) fn visit_page_envelopes<E>(
        &self,
        mut visit: impl FnMut(ObjectEnvelope) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        for (file, pages) in [
            (&self.selected_pages, self.manifest.selected_pages()),
            (&self.omitted_pages, self.manifest.omitted_pages()),
        ] {
            let mut spool = SpooledPages::open(file)?;
            for page in pages.iter().copied().map(Some).chain([None]) {
                match spool.next_envelope(page)? {
                    Some(envelope) => visit(envelope)?,
                    None => break,
                }
            }
        }
        Ok(())
    }
}
