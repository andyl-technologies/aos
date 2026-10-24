//! Counts actual retained cold17 decoder products without stage-based discounts.

use super::*;

impl RetainedCold17Collection {
    /// Names this owning census and its actual nested retained-owner visitors.
    ///
    /// This fixed DATA roster does not perform the walk or grant admission. It
    /// includes partial owners and both flatten iterators regardless of phase.
    pub(crate) fn retained_counter_scratch_data() -> usize {
        use crucible_node_transport::{
            reference_packet::service::complete_restore::activation::{
                restoration_activation_retained_counter_scratch_data,
                restoration_activation_retained_native_evidence_counter_scratch_data,
            },
            retained_metadata::RetainedProtocolMetadataFacts,
        };

        size_of::<&Self>()
            + size_of::<Counter>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<std::iter::Flatten<
                std::slice::Iter<'static, Option<parent_index::ParentIndex17Attempt>>,
            >>()
            + size_of::<&parent_index::ParentIndex17Attempt>()
            + size_of::<std::iter::Flatten<
                std::slice::Iter<'static, Vec<RetainedCold17Member>>,
            >>()
            + size_of::<&RetainedCold17Member>()
            + size_of::<&[Vec<RetainedCold17Member>; 3]>()
            + size_of::<&Vec<RetainedCold17Member>>()
            + size_of::<std::slice::Iter<'static, Vec<RetainedCold17Member>>>()
            + size_of::<[&ContentRef; 9]>()
            + size_of::<std::array::IntoIter<&ContentRef, 9>>()
            + size_of::<[&ContentRef; 7]>()
            + size_of::<std::array::IntoIter<&ContentRef, 7>>()
            + size_of::<&ContentRef>()
            + size_of::<&Value>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + parent_index::ParentIndex17Attempt::owning_counter_scratch_data()
            + NodeRuntime::capture_complete_archive_typed_counter_scratch_data()
            + NodeRuntime::original_json_value_counter_scratch_data()
            + current_controller17_counter_scratch_data()
            + historical_restored_settled_capture17_counter_scratch_data()
            + restored_settled_native17_counter_scratch_data()
            + CnpRestoredNode17DecodeAttempt::counter_scratch_data()
            + CnpRestoredSettledValidatedNode17::counter_scratch_data()
            + OriginalSourceRestoredSettled17Prelude::counter_scratch_data()
            + OriginalSourceRestoredSettled17DecodeAttempt::counter_scratch_data()
            + OriginalSourceRestoredSettled17Read::counter_scratch_data()
            // SourceRead's actual owning walk retains eleven simultaneous terms;
            // its parser counter separately names the five-slot decode views.
            + size_of::<[usize; 11]>()
            + size_of::<std::array::IntoIter<usize, 11>>()
            // Prelude's five-term owning fold has its own consumed iterator.
            + size_of::<std::array::IntoIter<usize, 5>>()
            // First-observation SDK and native evidence facts coexist until the
            // five-term fold; Producer owns its separate native facts/fold.
            + 3 * size_of::<RetainedProtocolMetadataFacts>()
            // Installation's own launch and installation facts coexist while
            // its independent retained field geometry is accumulated.
            + 2 * size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + restoration_activation_retained_native_evidence_counter_scratch_data()
            + restoration_activation_retained_counter_scratch_data()
            + crate::node_adapters::cnp::OriginalInitial15ArchivedGroup::terminal_counter_scratch_data()
            + super::super::initial15_history::HistoricalInitial15Scope17::counter_scratch_data()
    }

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
            initial15_group,
            historical_scope,
            terminal_cache: _,
            production_declaration: _,
        } = self;
        let mut count = Counter { bytes: 0, maximum };
        charge_member_banks_data(members, &mut count)?;
        count.add(
            parents
                .capacity()
                .checked_mul(size_of::<Option<parent_index::ParentIndex17Attempt>>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for parent in parents.iter().flatten() {
            count.add(parent.retained_requested_storage_data(maximum)?)?;
        }
        if let Some(group) = initial15_group {
            count.add(
                group
                    .retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?
                    .checked_sub(size_of::<
                        crate::node_adapters::cnp::OriginalInitial15ArchivedGroup,
                    >())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(historical) = historical_scope {
            count.add(historical.retained_requested_storage_data(maximum)?)?;
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
                prelude,
                source_attempt,
                source,
                source_decode_axes: _,
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
            if let Some(prelude) = prelude {
                count.add(prelude.retained_requested_storage_data(maximum)?)?;
            }
            if let Some(attempt) = source_attempt {
                count.add(attempt.retained_requested_storage_data(maximum)?)?;
            }
            if let Some(source) = source {
                count.add(source.retained_requested_storage_data(maximum)?)?;
            }
        }
        Ok(count.bytes)
    }
}

fn charge_member_banks_data(
    banks: &[Vec<RetainedCold17Member>; 3],
    count: &mut Counter,
) -> Result<(), RuntimeError> {
    for bank in banks {
        count.add(member_bank_requested_storage_data(bank.capacity())?)?;
    }
    Ok(())
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

#[cfg(test)]
mod member_bank_tests {
    use super::*;

    #[test]
    fn actual_reserved_empty_member_bank_is_charged_and_not_renewed() {
        // These are real uninitialized storage banks. No Collection, member,
        // archive handle, token or successful parser output is fabricated.
        let mut banks: [Vec<RetainedCold17Member>; 3] = std::array::from_fn(|_| Vec::new());
        let mut empty = Counter {
            bytes: 0,
            maximum: 0,
        };
        charge_member_banks_data(&banks, &mut empty).unwrap();
        assert_eq!(empty.bytes, 0);

        reserve_member_slot_data(&mut banks[1]).unwrap();
        assert!(banks[1].is_empty());
        assert_eq!(banks[1].capacity(), 1);
        let pointer = banks[1].as_ptr();
        let requested = member_bank_requested_storage_data(banks[1].capacity()).unwrap();
        let mut exact = Counter {
            bytes: 0,
            maximum: requested,
        };
        charge_member_banks_data(&banks, &mut exact).unwrap();
        assert_eq!(exact.bytes, requested);
        let mut short = Counter {
            bytes: 0,
            maximum: requested - 1,
        };
        assert!(charge_member_banks_data(&banks, &mut short).is_err());

        assert!(reserve_member_slot_data(&mut banks[1]).is_err());
        assert!(banks[1].is_empty());
        assert_eq!(banks[1].as_ptr(), pointer);
        assert_eq!(banks[1].capacity(), 1);
        assert!(banks[0].is_empty());
        assert_eq!(banks[0].capacity(), 0);

        reserve_member_slot_data(&mut banks[2]).unwrap();
        assert_ne!(banks[1].as_ptr(), banks[2].as_ptr());
        let mut independent = Counter {
            bytes: 0,
            maximum: requested * 2,
        };
        charge_member_banks_data(&banks, &mut independent).unwrap();
        assert_eq!(independent.bytes, requested * 2);
        assert!(member_bank_requested_storage_data(usize::MAX).is_err());
    }
}
