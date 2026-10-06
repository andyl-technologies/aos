//! Bounded immutable RAM closure transfer and root-difference traversal.
//!
//! Transfer publishes descendants before a root and authenticates destination
//! possession by complete reads. A stored closure is archive readiness only;
//! this module grants no machine ownership or live migration authority.

use crucible_protocol::ram_transfer::{
    MAX_TRANSFER_CHUNK_BYTES, RamTransferLimits, RamTransferMessage, RamTransferOffer,
};
use crucible_ram::RegionDescriptor;

use crate::content_store::{ContentId, StoreError};

use super::codec::{TreeNode, TreeRef};
use super::{
    LeasedRamRoot, RamRetention, RamStore, RamStoreError, RamTransferReceiver, RamTransferSender,
    RamTransferStep, Work, valid_length,
};

/// Counters describing an authenticated missing-content-only transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RamTransferReport {
    /// Objects newly copied to the destination.
    pub copied_objects: u64,
    /// Canonical bytes in newly copied objects.
    pub copied_bytes: u64,
    /// Existing objects whose actual destination bytes authenticated.
    pub authenticated_existing_objects: u64,
    /// Work visits recorded by the transfer coordinator, including repeated references.
    pub object_visits: u64,
}

/// Durable authenticated RAM archive closure with destination retention.
///
/// This receipt establishes complete local RAM possession. Device state, disk
/// overlays, scheduler state, and the rest of the whole-world closure still
/// require their own authenticated publication before a checkpoint is complete.
/// It never means that a destination process is restore-ready or owns execution.
#[derive(Clone, Debug)]
pub struct RamClosureStored {
    pub(super) root: LeasedRamRoot,
    pub(super) report: RamTransferReport,
}

impl RamClosureStored {
    /// Returns the independently retained destination RAM root.
    pub fn root(&self) -> &LeasedRamRoot {
        &self.root
    }

    /// Returns counters for the completed transfer.
    pub fn report(&self) -> RamTransferReport {
        self.report
    }
}

impl RamStore {
    /// Transfers an authenticated archive binding through bounded wire controls.
    ///
    /// The caller authenticates `whole_world_root` as the owning checkpoint in
    /// its selected archive inventory and keeps both transfer journals active.
    /// The selected store transport serves coordinate requests; every control
    /// passes the portable codec before either endpoint consumes it. This is an
    /// offline archive operation and does not grant live execution handoff.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid binding identities, unavailable or corrupt
    /// bytes, malformed controls, cancellation, resource caps, or durability.
    // crucible-lint: allow rust-allow -- explicit transfer inputs bind source, destination, durable operation, retention, and original supervision.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_archive_to(
        &self,
        source: &LeasedRamRoot,
        whole_world_root: ContentId,
        destination: &Self,
        destination_identity: &str,
        operation: [u8; 32],
        retention: &dyn RamRetention,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamClosureStored, RamStoreError> {
        let offer = RamTransferOffer {
            whole_world_root: whole_world_root.to_string(),
            ram_root: source.object_id().to_string(),
            root_record: source.record().encode(),
            destination: destination_identity.to_owned(),
            durable_placements: destination.durability.minimum_durable_placements(),
            limits: RamTransferLimits {
                objects: self
                    .limits
                    .maximum_object_visits
                    .min(destination.limits.maximum_object_visits),
                bytes: self
                    .limits
                    .maximum_io_bytes
                    .min(destination.limits.maximum_io_bytes),
                chunk_bytes: MAX_TRANSFER_CHUNK_BYTES,
            },
        };
        let mut sender = RamTransferSender::new(self.clone(), source.clone(), operation, offer)?;
        let encoded_offer = sender.offer().encode()?;
        let mut receiver = RamTransferReceiver::new(
            destination.clone(),
            retention,
            RamTransferMessage::decode(&encoded_offer)?,
        )?;
        // Storage and transport service share the same operational boundary.
        // A RefCell only sequences mutable callback access; no endpoint may hold
        // that borrow across its call into the peer.
        let boundary = std::cell::RefCell::new(boundary);
        let mut exchange = |request: RamTransferMessage| {
            let request = RamTransferMessage::decode(&request.encode()?)?;
            let response = sender.respond(request, &mut || (boundary.borrow_mut())())?;
            Ok(RamTransferMessage::decode(&response.encode()?)?)
        };
        match receiver.receive(&mut exchange, &mut || (boundary.borrow_mut())())? {
            RamTransferStep::ClosureStored(stored) => Ok(stored),
            RamTransferStep::Canceled => Err(RamStoreError::Canceled),
        }
    }

    /// Copies only missing objects while verifying every required realization.
    ///
    /// The caller holds the source lease throughout. Destination operation
    /// retention precedes discovery and publication; its root lease is installed
    /// only after all descendants authenticate under the destination durability
    /// floor. Traversal stores one binary path and one bounded object at a time.
    /// Existing-object hints are never accepted as proof of possession.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt or missing source bytes, corrupt destination
    /// bytes, cancellation, limits, retention loss, or insufficient durability.
    pub fn transfer_to(
        &self,
        source: &LeasedRamRoot,
        destination: &Self,
        retention: &dyn RamRetention,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamClosureStored, RamStoreError> {
        self.admit_topology(source.record.topology())?;
        destination.admit_ram_publication(source.record.topology(), source.record.scope())?;
        self.validate_root_catalogs(&source.record, &source.regions)?;
        // Both stores charge the same operation counter; neither endpoint gets
        // an additional budget by alternating reads between stores.
        let limits = super::RamStoreLimits {
            maximum_logical_bytes: self
                .limits
                .maximum_logical_bytes
                .min(destination.limits.maximum_logical_bytes),
            maximum_pages: self
                .limits
                .maximum_pages
                .min(destination.limits.maximum_pages),
            maximum_object_visits: self
                .limits
                .maximum_object_visits
                .min(destination.limits.maximum_object_visits),
            maximum_io_bytes: self
                .limits
                .maximum_io_bytes
                .min(destination.limits.maximum_io_bytes),
        };
        let mut work = Work::new(limits, boundary);
        let mut report = RamTransferReport::default();
        for (region, reference) in source
            .record
            .topology()
            .regions()
            .iter()
            .filter(|region| source.record.scope().includes(region.class()))
            .zip(&source.regions)
        {
            self.transfer_region(
                region,
                *reference,
                0,
                destination,
                retention,
                &mut report,
                &mut work,
            )?;
        }

        self.copy_object(
            source.object_id(),
            destination,
            retention,
            &mut report,
            &mut work,
        )?;
        let lease = retention.retain_root(source.object_id())?;
        if lease.root() != source.object_id() {
            return Err(RamStoreError::Invalid("destination root retention receipt"));
        }
        let root = LeasedRamRoot {
            record: source.record.clone(),
            regions: source.regions.clone(),
            lease,
        };
        report.object_visits = work.visits;
        Ok(RamClosureStored { root, report })
    }

    /// Visits differing logical page positions without loading a flat catalog.
    ///
    /// Equal authenticated subtrees are pruned. This is a logical comparison;
    /// it does not prove destination possession or replace closure transfer.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched topology or scope, invalid metadata,
    /// cancellation, a visitor error, or exhausted traversal budgets.
    pub fn visit_differing_pages(
        &self,
        before: &LeasedRamRoot,
        after: &LeasedRamRoot,
        visitor: &mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<u64, RamStoreError> {
        self.admit_topology(before.record.topology())?;
        self.admit_topology(after.record.topology())?;
        if before.record.topology() != after.record.topology()
            || before.record.scope() != after.record.scope()
        {
            return Err(RamStoreError::Invalid("RAM comparison topology or scope"));
        }
        self.validate_root_catalogs(&before.record, &before.regions)?;
        self.validate_root_catalogs(&after.record, &after.regions)?;
        let mut work = Work::new(self.limits, boundary);
        let mut changed = 0_u64;
        for ((region, before), after) in before
            .record
            .topology()
            .regions()
            .iter()
            .filter(|region| before.record.scope().includes(region.class()))
            .zip(&before.regions)
            .zip(&after.regions)
        {
            self.diff_region(
                region.id(),
                *before,
                *after,
                0,
                visitor,
                &mut changed,
                &mut work,
            )?;
        }
        Ok(changed)
    }

    // crucible-lint: allow rust-allow -- recursive transfer keeps page geometry, destination retention, receipt counters, and the original work budget explicit.
    #[allow(clippy::too_many_arguments)]
    fn transfer_region(
        &self,
        region: &RegionDescriptor,
        reference: TreeRef,
        first: u64,
        destination: &Self,
        retention: &dyn RamRetention,
        report: &mut RamTransferReport,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        match self.read_tree(reference, work)? {
            TreeNode::Padding => {}
            TreeNode::Leaf { page, digest } => {
                let bytes = self.read_page_object(page, digest, work)?;
                if bytes.len() != valid_length(region, first)? {
                    return Err(RamStoreError::Invalid("transferred page valid length"));
                }
                self.copy_object(page, destination, retention, report, work)?;
            }
            TreeNode::Branch { left, right } => {
                self.transfer_region(region, left, first, destination, retention, report, work)?;
                self.transfer_region(
                    region,
                    right,
                    first + (1_u64 << (reference.height - 1)),
                    destination,
                    retention,
                    report,
                    work,
                )?;
            }
        }
        self.copy_object(reference.id, destination, retention, report, work)
    }

    fn copy_object(
        &self,
        id: ContentId,
        destination: &Self,
        retention: &dyn RamRetention,
        report: &mut RamTransferReport,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        retention.retain_object(id)?;
        let source = self.read_envelope(id, work)?;
        match destination.read_envelope(id, work) {
            Ok(existing) => {
                if existing != source {
                    return Err(StoreError::Corrupt { id }.into());
                }
                // Re-put produces authenticated durable placement evidence even
                // when the object was already present in a composed backend.
                destination.put_envelope(&existing, id.kind(), retention, work)?;
                report.authenticated_existing_objects = report
                    .authenticated_existing_objects
                    .checked_add(1)
                    .ok_or(RamStoreError::Limit("transfer object count"))?;
            }
            Err(RamStoreError::Store(StoreError::NotFound { .. })) => {
                destination.put_envelope(&source, id.kind(), retention, work)?;
                report.copied_objects = report
                    .copied_objects
                    .checked_add(1)
                    .ok_or(RamStoreError::Limit("transfer object count"))?;
                report.copied_bytes = report
                    .copied_bytes
                    .checked_add(source.canonical_bytes().len() as u64)
                    .ok_or(RamStoreError::Limit("transfer copied bytes"))?;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    // crucible-lint: allow rust-allow -- comparison keeps both authenticated references, logical position, visitor, counter, and original work budget explicit.
    #[allow(clippy::too_many_arguments)]
    fn diff_region(
        &self,
        region: &str,
        before: TreeRef,
        after: TreeRef,
        first: u64,
        visitor: &mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
        changed: &mut u64,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        // Metadata is fetched even for equal roots: opaque root digests grant
        // identity, not proof that a supplied storage realization is authentic.
        let old = self.read_tree(before, work)?;
        let new = self.read_tree(after, work)?;
        if before.digest == after.digest {
            return Ok(());
        }
        match (old, new) {
            (TreeNode::Leaf { .. }, TreeNode::Leaf { .. }) => {
                visitor(region, first)?;
                *changed = changed
                    .checked_add(1)
                    .ok_or(RamStoreError::Limit("different pages"))?;
                Ok(())
            }
            (
                TreeNode::Branch {
                    left: old_left,
                    right: old_right,
                },
                TreeNode::Branch { left, right },
            ) => {
                self.diff_region(region, old_left, left, first, visitor, changed, work)?;
                self.diff_region(
                    region,
                    old_right,
                    right,
                    first + (1_u64 << (after.height - 1)),
                    visitor,
                    changed,
                    work,
                )
            }
            _ => Err(RamStoreError::Invalid("RAM difference tree shape")),
        }
    }
}
