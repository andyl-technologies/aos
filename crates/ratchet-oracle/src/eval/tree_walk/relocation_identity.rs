//! Relocation repair for TreeWalk-owned address-identity side tables.
//!
//! When minor collection relocates a live `Value`, several evaluator
//! accelerators may retain only a thunk's payload address. This module stages
//! the young-key classification before live heap mutation and then performs an
//! allocation-free commit: survivor keys move to their forwarding destination,
//! dead young keys are discarded before nursery addresses can be reused, and
//! advisory caches whose keys or recipes retain relocation-sensitive values are
//! cleared.

use std::ptr::NonNull;

use super::*;

const RELOCATION_IDENTITY_REPAIR_TABLE: &str = "tree-walk relocation identity repair";

/// Stages the allocation-free identity mutations for one minor-GC commit.
#[derive(Debug)]
pub(super) struct TreeWalkRelocationIdentityRepairPlan {
    relocations: Vec<(u64, u64)>,
    dead_young_keys: Vec<u64>,
}

impl TreeWalk {
    /// Classifies TreeWalk-owned identities before live heap mutation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if staging storage cannot be reserved, a
    /// forwarding slot is empty, or an identity key no longer resolves to a
    /// valid heap generation.
    pub(super) fn stage_relocation_identity_repair(
        &self,
        forwarding_slots: &[MinorGcForwardingSlot],
    ) -> Result<TreeWalkRelocationIdentityRepairPlan, EvalHeapError> {
        let mut forwarding_addresses = Vec::new();
        forwarding_addresses
            .try_reserve_exact(forwarding_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: forwarding_slots.len(),
            })?;
        for (index, slot) in forwarding_slots.iter().copied().enumerate() {
            let forwarded =
                slot.forwarded_value()
                    .ok_or(EvalHeapError::CollectorPollForwardingSlotEmpty {
                        index,
                        address: slot.source(),
                    })?;
            let ResolvedValueGeneration::Heap { address, .. } = forwarded else {
                debug_assert!(false, "minor-GC forwarding values are heap-backed");
                continue;
            };
            forwarding_addresses.push((slot.source().address_bits(), address.address_bits()));
        }
        forwarding_addresses.sort_unstable_by_key(|(source, _)| *source);
        debug_assert!(
            forwarding_addresses
                .windows(2)
                .all(|pair| pair[0].0 != pair[1].0),
            "minor-GC forwarding sources are unique"
        );

        let mut option_identities = self
            .options
            .option_read_observer
            .as_ref()
            .map(|observer| observer.provenance_identities())
            .unwrap_or_default();
        option_identities.sort_unstable_by_key(|(identity, _)| *identity);
        let candidate_count = self
            .lazy_identity_thunks
            .len()
            .saturating_add(self.lazy_foldl_initial_thunks.len())
            .saturating_add(self.tier1_publish_slots.len())
            .saturating_add(option_identities.len());
        let mut candidates = Vec::new();
        candidates.try_reserve_exact(candidate_count).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: candidate_count,
            }
        })?;
        candidates.extend(
            self.lazy_identity_thunks
                .iter()
                .map(|identity| (*identity, ValueTag::Thunk)),
        );
        candidates.extend(
            self.lazy_foldl_initial_thunks
                .iter()
                .map(|identity| (*identity, ValueTag::Thunk)),
        );
        candidates.extend(
            self.tier1_publish_slots
                .keys()
                .map(|identity| (*identity, ValueTag::Thunk)),
        );
        candidates.extend(option_identities.iter().copied());
        candidates.sort_unstable_by_key(|(identity, _)| *identity);
        candidates.dedup_by(|right, left| {
            if right.0 != left.0 {
                return false;
            }
            debug_assert_eq!(
                right.1, left.1,
                "one relocation identity cannot name values with different tags"
            );
            true
        });

        let mut relocations = Vec::new();
        relocations
            .try_reserve_exact(candidates.len().min(forwarding_addresses.len()))
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: candidates.len().min(forwarding_addresses.len()),
            })?;
        let mut dead_young_keys = Vec::new();
        dead_young_keys
            .try_reserve_exact(candidates.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: candidates.len(),
            })?;
        for (key, tag) in candidates {
            let value = relocation_identity_value(key, tag)?;
            let source_address = value.as_heap_ptr()?.as_ptr() as usize;
            if let Ok(index) =
                forwarding_addresses.binary_search_by_key(&source_address, |(source, _)| *source)
            {
                let destination_address = forwarding_addresses[index].1;
                let destination_pointer = NonNull::new(destination_address as *mut _).ok_or(
                    EvalHeapError::GenerationalGc(GenerationalGcError::NullAddress),
                )?;
                let destination = Value::heap(tag, destination_pointer)?;
                relocations.push((key, destination.relocation_sensitive_identity_bits()));
            } else if self.heap.generation(value)? == HeapGeneration::Young {
                dead_young_keys.push(key);
            }
        }
        relocations.sort_unstable_by_key(|(source, _)| *source);
        dead_young_keys.sort_unstable();

        Ok(TreeWalkRelocationIdentityRepairPlan {
            relocations,
            dead_young_keys,
        })
    }

    /// Applies a staged identity repair without allocating or failing.
    pub(super) fn commit_relocation_identity_repair(
        &mut self,
        plan: TreeWalkRelocationIdentityRepairPlan,
    ) {
        prune_and_rekey_set(
            &mut self.lazy_identity_thunks,
            &plan.relocations,
            &plan.dead_young_keys,
        );
        prune_and_rekey_set(
            &mut self.lazy_foldl_initial_thunks,
            &plan.relocations,
            &plan.dead_young_keys,
        );
        prune_and_rekey_map(
            &mut self.tier1_publish_slots,
            &plan.relocations,
            &plan.dead_young_keys,
        );
        if let Some(observer) = &self.options.option_read_observer {
            observer.repair_relocated_identities(&plan.relocations, &plan.dead_young_keys);
        }
        self.memo_unhashable_values.clear();
        self.genlist_elem_at_add_one_plans.clear();
    }
}

/// Rebuilds one side-table identity before the collector mutates live values.
fn relocation_identity_value(key: u64, tag: ValueTag) -> Result<Value, EvalHeapError> {
    #[cfg(feature = "candidate_c_value")]
    let value = {
        let word = crate::value::compressed::CompressedValueWord::from_raw(key).map_err(|_| {
            EvalHeapError::UnknownPointer {
                tag,
                address: key as usize,
            }
        })?;
        Value::from_word(word)
    };
    #[cfg(not(feature = "candidate_c_value"))]
    let value = {
        let address = GcHeapAddress::new(key as usize)?;
        let pointer = NonNull::new(address.address_bits() as *mut _).ok_or(
            EvalHeapError::GenerationalGc(GenerationalGcError::NullAddress),
        )?;
        Value::heap(tag, pointer)?
    };
    if value.tag() != tag || !value.tag().is_heap() {
        return Err(EvalHeapError::UnknownPointer {
            tag,
            address: key as usize,
        });
    }
    Ok(value)
}

/// Looks up one source in the sorted survivor relocation table.
#[cfg(test)]
fn relocation_destination(relocations: &[(u64, u64)], source: u64) -> Option<u64> {
    let index = relocations
        .binary_search_by_key(&source, |(candidate, _)| *candidate)
        .ok()?;
    Some(relocations[index].1)
}

/// Removes dead young identities and moves surviving identities in one set.
fn prune_and_rekey_set(
    identities: &mut HashSet<u64>,
    relocations: &[(u64, u64)],
    dead_young_keys: &[u64],
) {
    identities.retain(|key| dead_young_keys.binary_search(key).is_err());
    for &(source, destination) in relocations {
        if identities.remove(&source) {
            identities.insert(destination);
        }
    }
}

/// Removes dead young identities and moves surviving metadata in one map.
fn prune_and_rekey_map<T>(
    identities: &mut HashMap<u64, T>,
    relocations: &[(u64, u64)],
    dead_young_keys: &[u64],
) {
    identities.retain(|key, _| dead_young_keys.binary_search(key).is_err());
    for &(source, destination) in relocations {
        if let Some(value) = identities.remove(&source) {
            let displaced = identities.insert(destination, value);
            debug_assert!(
                displaced.is_none(),
                "fresh minor-GC destinations cannot own identity metadata"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    #[test]
    fn tree_walk_repair_rekeys_live_side_tables_and_clears_advisory_memo_keys() {
        let ir = lower("let xs = [ 10 20 ]; in (i: builtins.elemAt xs (i + 1))");
        let observer = OptionReadObserver::default();
        let mut options = TreeWalkOptions::default();
        options.set_option_read_observer(observer.clone());
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let generator = evaluator.eval_root().expect("generator evaluates");
        assert!(evaluator.is_genlist_elem_at_add_one_generator(generator));
        assert!(!evaluator.genlist_elem_at_add_one_plans.is_empty());
        let survivor = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("survivor thunk allocates");
        let dead = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(2)))
            .expect("dead thunk allocates");
        let destination_value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(3)))
            .expect("destination thunk allocates");
        let survivor_address = survivor
            .as_heap_ptr()
            .expect("survivor is heap-backed")
            .as_ptr() as usize;
        let destination_address = destination_value
            .as_heap_ptr()
            .expect("destination is heap-backed")
            .as_ptr() as usize;
        let survivor_key = survivor.relocation_sensitive_identity_bits();
        let dead_key = dead.relocation_sensitive_identity_bits();
        let forwarding = MinorGcForwardingSlot::with_forwarded_value(
            GcHeapAddress::new(survivor_address).expect("source is aligned"),
            ResolvedValueGeneration::young(
                GcHeapAddress::new(destination_address).expect("destination is aligned"),
            ),
        );
        evaluator
            .lazy_identity_thunks
            .extend([survivor_key, dead_key]);
        evaluator
            .lazy_foldl_initial_thunks
            .extend([survivor_key, dead_key]);
        evaluator
            .tier1_publish_slots
            .insert(survivor_key, OpaqueTier1Slot::new(1, Box::new("survivor")));
        evaluator
            .tier1_publish_slots
            .insert(dead_key, OpaqueTier1Slot::new(2, Box::new("dead")));
        evaluator.memo_unhashable_values.insert(survivor_key);
        observer.associate(survivor, vec![b"live".to_vec()]);
        observer.associate(dead, vec![b"dead".to_vec()]);

        let plan = evaluator
            .stage_relocation_identity_repair(&[forwarding])
            .expect("identity repair stages before mutation");
        evaluator.commit_relocation_identity_repair(plan);

        let destination_key = destination_value.relocation_sensitive_identity_bits();
        assert_eq!(
            evaluator.lazy_identity_thunks,
            HashSet::from([destination_key])
        );
        assert_eq!(
            evaluator.lazy_foldl_initial_thunks,
            HashSet::from([destination_key])
        );
        assert!(evaluator.tier1_publish_slots.contains_key(&destination_key));
        assert!(!evaluator.tier1_publish_slots.contains_key(&survivor_key));
        assert!(!evaluator.tier1_publish_slots.contains_key(&dead_key));
        assert!(evaluator.memo_unhashable_values.is_empty());
        assert!(evaluator.genlist_elem_at_add_one_plans.is_empty());
        assert_eq!(
            observer.provenance(destination_value),
            vec![vec![b"live".to_vec()]]
        );
        assert!(observer.provenance(dead).is_empty());
    }

    #[test]
    fn identity_sets_rekey_survivors_and_prune_dead_young_keys() {
        let mut identities = HashSet::from([0x10, 0x20, 0x30]);

        prune_and_rekey_set(&mut identities, &[(0x10, 0x110)], &[0x20]);

        assert_eq!(identities, HashSet::from([0x30, 0x110]));
    }

    #[test]
    fn identity_maps_move_metadata_without_reallocation() {
        let mut identities = HashMap::from([(0x10, "live"), (0x20, "dead"), (0x30, "old")]);

        prune_and_rekey_map(&mut identities, &[(0x10, 0x110)], &[0x20]);

        assert_eq!(identities, HashMap::from([(0x30, "old"), (0x110, "live")]));
    }

    #[test]
    fn relocation_lookup_uses_the_sorted_source_table() {
        let relocations = [(0x10, 0x110), (0x20, 0x120)];

        assert_eq!(relocation_destination(&relocations, 0x20), Some(0x120));
        assert_eq!(relocation_destination(&relocations, 0x30), None);
    }
}
