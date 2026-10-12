//! Attributes every physical discovery event exclusively to one local stream.
//!
//! A reached physical level has at most one active divergent region. Diagnostic
//! regions may overlap in time, but each actual event has exactly one owner and
//! contributes once to scalar totals. Repeated reads remain repeated events.

use alloc::vec::Vec;

use super::frontier::add;
use super::{DiscoveryWork, Error, PhysicalEvent, PhysicalEventKind};
use crate::tree_format::MAX_TREE_LEVEL;

/// Owns one local stream's event ledger and exclusive region assignment.
pub(super) struct Recorder {
    /// Exact scalar total of the retained physical events.
    pub(super) work: DiscoveryWork,
    /// Actual event batches in execution order.
    pub(super) events: Vec<PhysicalEvent>,
    regions: [Option<usize>; MAX_TREE_LEVEL as usize + 1],
}

impl Recorder {
    /// Starts ordinary traversal accounting with no active divergent cut.
    pub(super) fn new() -> Self {
        Self {
            work: DiscoveryWork::default(),
            events: Vec::new(),
            regions: [None; MAX_TREE_LEVEL as usize + 1],
        }
    }

    /// Checks the active owner directly at one physical level.
    ///
    /// # Errors
    /// Rejects unsupported levels and counter overflow.
    pub(super) fn owner(&mut self, level: u8) -> Result<Option<usize>, Error> {
        self.charge(level, PhysicalEventKind::BoundaryCheck, 1)?;
        self.regions
            .get(usize::from(level))
            .copied()
            .ok_or(Error::Limit)
    }

    /// Opens exclusive attribution at the actual affected physical level.
    ///
    /// # Errors
    /// Rejects unsupported levels, an existing connected owner and counter overflow.
    pub(super) fn open(&mut self, level: u8, region: usize) -> Result<(), Error> {
        self.charge(level, PhysicalEventKind::BoundaryCheck, 1)?;
        let owner = self
            .regions
            .get_mut(usize::from(level))
            .ok_or(Error::Limit)?;
        if owner.is_some() {
            return Err(Error::Source);
        }
        *owner = Some(region);
        Ok(())
    }

    /// Ends attribution at a compatible recovered cut.
    ///
    /// # Errors
    /// Rejects unsupported physical levels and counter overflow.
    pub(super) fn close(&mut self, level: u8) -> Result<(), Error> {
        self.charge(level, PhysicalEventKind::BoundaryCheck, 1)?;
        *self
            .regions
            .get_mut(usize::from(level))
            .ok_or(Error::Limit)? = None;
        Ok(())
    }

    /// Charges one actual event batch to exactly one occurrence and level.
    ///
    /// # Errors
    /// Rejects counter overflow and unsupported physical levels.
    pub(super) fn charge(
        &mut self,
        level: u8,
        kind: PhysicalEventKind,
        amount: usize,
    ) -> Result<(), Error> {
        let region = *self.regions.get(usize::from(level)).ok_or(Error::Limit)?;
        let counter = match kind {
            PhysicalEventKind::BoundaryCheck => &mut self.work.boundary_checks,
            PhysicalEventKind::PropertyRead => &mut self.work.property_reads,
            PhysicalEventKind::NodeRead => &mut self.work.node_reads,
            PhysicalEventKind::ItemRead => &mut self.work.item_reads,
            PhysicalEventKind::ChildRead => &mut self.work.child_reads,
            PhysicalEventKind::Comparison => &mut self.work.comparisons,
            PhysicalEventKind::FrontierCheck => &mut self.work.frontier_checks,
            PhysicalEventKind::SkippedSubtree => &mut self.work.skipped_subtrees,
        };
        add(counter, amount)?;
        if amount != 0 {
            self.events.push(PhysicalEvent {
                level,
                kind,
                amount,
                boundary: region,
            });
        }
        Ok(())
    }
}
