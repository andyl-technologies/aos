//! Counts actual installation custody through every initialized prefix.
//!
//! The original enclosing owner independently retains and counts the immutable
//! policy and selected-launch allocation. Their shared edge is checked before
//! this additional component is measured. Archive and model backing follows its
//! actual destination; failed attempts are measured without a validated17 loan.
//! Kernel resources, traversal work and phase admission remain separate.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts, aliases::MetadataSharedKind,
    requested_metadata_backing_storage_data,
};
use std::mem::size_of;

impl Native18ModelInstallation {
    /// Counts this inline owner and every independently retained child allocation.
    ///
    /// The genuine enclosing Source separately counts the same original policy
    /// and launch backing. Only that actual shared policy edge is excluded here;
    /// equal DATA in another allocation cannot authorize the exclusion. Control
    /// and archive headers already live inline in this owner. Their independently
    /// owned payloads remain counted after failure, binding and installation.
    /// Other shared observations conservatively keep their defining charges.
    ///
    /// Callers admit this traversal and its counter before entry. This DATA
    /// changes no budget, clears no attempt and authenticates no native phase.
    /// Socket descriptors and kernel backing require separate original funding.
    ///
    /// # Errors
    /// Refuses foreign origin or another policy allocation, invalid child
    /// geometry, arithmetic overflow or an independently short restriction.
    pub(crate) fn additional_retained_requested_storage_data(
        &self,
        original_policy: &Rc<NativeImport18PolicyData>,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.authenticate_origin()?;
        if !Rc::ptr_eq(&self.policy, original_policy) {
            return Err(refused18());
        }

        let Self {
            process: _,
            thread: _,
            failed: _,
            installed: _,
            policy: _,
            inputs,
            boundary,
            archive,
            control,
            hold,
            completed,
        } = self;
        let mut observer = MetadataObserver::new();
        let mut requested = size_of::<Self>();
        if let Some(inputs) = inputs {
            let Native18ModelInstallationInputs {
                target,
                archive,
                effect_socket: _,
            } = inputs;
            if let Some((selection, coordinator)) = target {
                observer.observe(selection)?;
                observer.observe(coordinator)?;
            }
            if let Some(archive) = archive {
                requested = checked_sum(
                    requested,
                    archive.retained_requested_storage_data(usize::MAX)?,
                )?;
            }
        }
        if let Some(boundary) = boundary {
            let PacketModelCaptureBoundaryData {
                local_cursor,
                gate_closed,
                retained_outputs,
                earliest_pending_completion,
                inventory_hash,
            } = boundary;
            observer.observe(local_cursor)?;
            observer.observe(gate_closed)?;
            observer.observe(retained_outputs)?;
            observer.observe(earliest_pending_completion)?;
            observer.observe(inventory_hash)?;
        }
        if let Some(archive) = archive {
            let backing = archive
                .retained_requested_storage_data(usize::MAX)?
                .checked_sub(size_of::<RestoredSettledNative18ModelAdoption>())
                .ok_or_else(refused18)?;
            requested = checked_sum(requested, backing)?;
        }
        if let Some(control) = control {
            control.observe_restored_settled_history_metadata_data(&mut observer)?;
        }
        if let Some(hold) = hold {
            let counted_by_control = control
                .as_ref()
                .and_then(|control| control.complete_restored_hold.as_ref())
                .is_some_and(|actual| Rc::ptr_eq(actual, hold));
            if !counted_by_control {
                observer.shared_original(
                    MetadataSharedKind::NativeRestoredPhysicalHold,
                    hold.as_ref(),
                )?;
                hold.observe_settled_history_metadata_data(&mut observer)?;
            }
        }
        match completed {
            Some(CurrentModel18Program::Producer(program)) => observer.observe(program)?,
            Some(CurrentModel18Program::Reactive(program)) => observer.observe(program)?,
            None => {}
        }
        requested = checked_sum(
            requested,
            requested_metadata_backing_storage_data(&observer.finish())?,
        )?;
        if requested > maximum {
            return Err(ProviderError::ResourceExhausted(
                "native18 installation retained storage",
            ));
        }
        Ok(requested)
    }

    /// Names fixed census controls beside independent traversal and compiler frames.
    ///
    /// These controls cover the actual observer, identity checks, field loans and
    /// delegated child counters. They are not a complete Commit construction row
    /// or permission to run the census outside its enclosing admitted traversal.
    pub(crate) fn retained_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Rc<NativeImport18PolicyData>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<&Native18ModelInstallationInputs>()
            + size_of::<&PacketModelCaptureBoundaryData>()
            + size_of::<&RestoredSettledNative18ModelAdoption>()
            + size_of::<&PacketControl>()
            + size_of::<&Rc<PacketCompleteRestorePhysicalHold>>()
            + size_of::<Option<&Rc<PacketCompleteRestorePhysicalHold>>>()
            + size_of::<&Option<CurrentModel18Program>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<usize>() * 4
            + size_of::<bool>()
            + size_of::<Result<usize, ProviderError>>() * 2
            + PacketControl::restored_settled_history_counter_scratch_data()
            + RestoredSettledNative18ModelAdoption::counter_scratch_data()
            + crate::retained_metadata::retained_native_coordinator_counter_scratch_data()
    }
}

fn checked_sum(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused18)
}

#[cfg(test)]
mod tests;
