//! Relocation repair for TreeWalk-owned address-identity side tables.
//!
//! Minor collection rewrites every live `Value`, but several evaluator
//! accelerators retain only a thunk's payload address. This module stages the
//! young-key classification before live heap mutation and then performs an
//! allocation-free commit: survivor keys move to their forwarding destination,
//! dead young keys are discarded before nursery addresses can be reused, and
//! the advisory memo decline cache is cleared.

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
        let mut relocations = Vec::new();
        relocations
            .try_reserve_exact(forwarding_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: forwarding_slots.len(),
            })?;
        for (index, slot) in forwarding_slots.iter().copied().enumerate() {
            let forwarded = slot.forwarded_value().ok_or(
                EvalHeapError::CollectorPollForwardingSlotEmpty {
                    index,
                    address: slot.source(),
                },
            )?;
            let ResolvedValueGeneration::Heap { address, .. } = forwarded else {
                debug_assert!(false, "minor-GC forwarding values are heap-backed");
                continue;
            };
            relocations.push((
                slot.source().address_bits() as u64,
                address.address_bits() as u64,
            ));
        }
        relocations.sort_unstable_by_key(|(source, _)| *source);
        debug_assert!(
            relocations
                .windows(2)
                .all(|pair| pair[0].0 != pair[1].0),
            "minor-GC forwarding sources are unique"
        );

        let candidate_count = self
            .lazy_identity_thunks
            .len()
            .saturating_add(self.lazy_foldl_initial_thunks.len())
            .saturating_add(self.tier1_publish_slots.len());
        let mut candidates = Vec::new();
        candidates.try_reserve_exact(candidate_count).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: candidate_count,
            }
        })?;
        candidates.extend(self.lazy_identity_thunks.iter().copied());
        candidates.extend(self.lazy_foldl_initial_thunks.iter().copied());
        candidates.extend(self.tier1_publish_slots.keys().copied());
        candidates.sort_unstable();
        candidates.dedup();

        let mut dead_young_keys = Vec::new();
        dead_young_keys
            .try_reserve_exact(candidates.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: RELOCATION_IDENTITY_REPAIR_TABLE,
                entries: candidates.len(),
            })?;
        for key in candidates {
            if relocation_destination(&relocations, key).is_none()
                && self.relocation_identity_key_is_young(key)?
            {
                dead_young_keys.push(key);
            }
        }

        Ok(TreeWalkRelocationIdentityRepairPlan {
            relocations,
            dead_young_keys,
        })
    }

    /// Returns whether a thunk identity still names a young heap object.
    fn relocation_identity_key_is_young(&self, key: u64) -> Result<bool, EvalHeapError> {
        let address = GcHeapAddress::new(key as usize)?;
        let Some(pointer) = NonNull::new(address.address_bits() as *mut _) else {
            return Err(EvalHeapError::GenerationalGc(
                GenerationalGcError::NullAddress,
            ));
        };
        let thunk = Value::thunk(pointer).map_err(EvalHeapError::Value)?;
        Ok(self.heap.generation(thunk)? == HeapGeneration::Young)
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
        self.memo_unhashable_values.clear();
    }
}

/// Looks up one source in the sorted survivor relocation table.
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
        nix_lower(
            resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers")
    }

    #[test]
    fn tree_walk_repair_rekeys_live_side_tables_and_clears_advisory_memo_keys() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let survivor = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("survivor thunk allocates");
        let dead = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(2)))
            .expect("dead thunk allocates");
        let survivor_key = survivor
            .as_heap_ptr()
            .expect("survivor is heap-backed")
            .as_ptr() as usize as u64;
        let dead_key = dead
            .as_heap_ptr()
            .expect("dead thunk is heap-backed")
            .as_ptr() as usize as u64;
        let destination = GcHeapAddress::new(0x1000).expect("destination is aligned");
        let forwarding = MinorGcForwardingSlot::with_forwarded_value(
            GcHeapAddress::new(survivor_key as usize).expect("source is aligned"),
            ResolvedValueGeneration::young(destination),
        );
        evaluator.lazy_identity_thunks.extend([survivor_key, dead_key]);
        evaluator
            .lazy_foldl_initial_thunks
            .extend([survivor_key, dead_key]);
        evaluator.tier1_publish_slots.insert(
            survivor_key,
            OpaqueTier1Slot::new(1, Box::new("survivor")),
        );
        evaluator.tier1_publish_slots.insert(
            dead_key,
            OpaqueTier1Slot::new(2, Box::new("dead")),
        );
        evaluator.memo_unhashable_values.insert(survivor_key);

        let plan = evaluator
            .stage_relocation_identity_repair(&[forwarding])
            .expect("identity repair stages before mutation");
        evaluator.commit_relocation_identity_repair(plan);

        let destination_key = destination.address_bits() as u64;
        assert_eq!(evaluator.lazy_identity_thunks, HashSet::from([destination_key]));
        assert_eq!(
            evaluator.lazy_foldl_initial_thunks,
            HashSet::from([destination_key])
        );
        assert!(evaluator.tier1_publish_slots.contains_key(&destination_key));
        assert!(!evaluator.tier1_publish_slots.contains_key(&survivor_key));
        assert!(!evaluator.tier1_publish_slots.contains_key(&dead_key));
        assert!(evaluator.memo_unhashable_values.is_empty());
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

        assert_eq!(
            identities,
            HashMap::from([(0x30, "old"), (0x110, "live")])
        );
    }

    #[test]
    fn relocation_lookup_uses_the_sorted_source_table() {
        let relocations = [(0x10, 0x110), (0x20, 0x120)];

        assert_eq!(relocation_destination(&relocations, 0x20), Some(0x120));
        assert_eq!(relocation_destination(&relocations, 0x30), None);
    }
}
