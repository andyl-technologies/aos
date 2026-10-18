//! Counts actual retained cold17 decoder products without stage-based discounts.

use super::*;

impl RetainedCold17Collection {
    /// Counts backing of every retained success and failure owner independently.
    ///
    /// The enclosing attempt or Source separately charges this inline root.
    /// Equal literals and shared Rc aliases are conservatively charged per owner;
    /// saved capacity evidence never substitutes for actual new decoder layouts.
    ///
    /// # Errors
    /// Refuses arithmetic or defining visitor overflow and the admitted ceiling.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            archive_index: _,
            process: _,
            thread: _,
            members,
            parents,
        } = self;
        let mut count = Counter { bytes: 0, maximum };
        count.add(
            parents
                .capacity()
                .checked_mul(size_of::<Option<parent_index::ParentIndex17Attempt>>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for parent in parents.iter().flatten() {
            count.add(parent.retained_requested_storage_data(maximum)?)?;
        }
        for member in members.iter().flatten() {
            let RetainedCold17Member {
                owner_index: _,
                journal_reference,
                journal,
                objects,
                ancestry,
                cut,
                controller,
                sdk_capture,
                native_limits,
                native_attempt,
                native,
                node_reference,
                route,
                node_attempt,
                node,
                semantic,
                source,
            } = member;
            if let Some(reference) = journal_reference {
                count.reference(reference)?;
            }
            if let Some(journal) = journal {
                count.json(journal)?;
            }
            if let Some(objects) = objects {
                let PacketRestoredSettledJournal17Objects {
                    snapshot,
                    before,
                    control,
                    anchor,
                    after,
                    host_protocol,
                    semantic,
                    runtime_object,
                    coordinator_checkpoint,
                } = objects;
                for reference in [
                    snapshot,
                    before,
                    control,
                    anchor,
                    after,
                    host_protocol,
                    semantic,
                    runtime_object,
                    coordinator_checkpoint,
                ] {
                    count.reference(reference)?;
                }
            }
            if let Some(ancestry) = ancestry {
                let PacketRestoredSettledAncestry17 {
                    parent_archive_index,
                    parent_manifest,
                    first_semantic,
                    first_journal,
                    first_observation,
                    restoration_commit,
                    restoration_hold,
                } = ancestry;
                for reference in [
                    parent_archive_index,
                    parent_manifest,
                    first_semantic,
                    first_journal,
                    first_observation,
                    restoration_commit,
                    restoration_hold,
                ] {
                    count.reference(reference)?;
                }
            }
            if let Some(cut) = cut {
                let PacketRestoredSettledHistoryCut17 {
                    prefix,
                    next_sequence: _,
                } = cut;
                count.reference(prefix)?;
            }
            if let Some(controller) = controller {
                count.add(
                    controller
                        .retained_requested_storage_data(maximum)
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )?;
            }
            if let Some(sdk) = sdk_capture {
                let facts = sdk
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                count.add(PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(&facts, maximum)?)?;
            }
            // Exact original constructor policy is fixed Copy DATA, not heap.
            fn require_copy<T: Copy>(_: &T) {}
            require_copy(native_limits);
            if let Some(attempt) = native_attempt {
                count.add(
                    attempt
                        .retained_requested_storage_data(maximum)
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )?;
            }
            if let Some(native) = native {
                count.add(
                    native
                        .retained_requested_storage_data(maximum)
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )?;
            }
            if let Some(reference) = node_reference {
                count.reference(reference)?;
            }
            if let Some(route) = route {
                count.add(NodeRuntime::capture_route_storage_data(route, maximum)?)?;
            }
            if let Some(attempt) = node_attempt {
                count.add(attempt.retained_requested_storage_data(maximum)?)?;
            }
            if let Some(node) = node {
                count.add(node.retained_requested_storage_data(maximum)?)?;
            }
            if let Some(semantic) = semantic {
                count.add(NodeRuntime::capture_shared_allocation_storage::<Value>())?;
                count.json(semantic.as_ref())?;
            }
            if let Some(source) = source {
                count.add(source.retained_requested_storage_data(maximum)?)?;
            }
        }
        Ok(count.bytes)
    }
}

struct Counter {
    bytes: usize,
    maximum: usize,
}

impl Counter {
    fn add(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn json(&mut self, value: &Value) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::original_json_value_requested_storage_data(
            value,
            self.maximum,
        )?)
    }

    fn reference(&mut self, reference: &ContentRef) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::capture_reference_storage(reference)?)
    }
}
