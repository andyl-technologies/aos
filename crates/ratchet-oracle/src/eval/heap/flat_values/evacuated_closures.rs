//! Closure stores owned by a compact Candidate-C generation.
//!
//! This is the first store owner for a compact evacuated generation. Merely
//! constructing it does not install routing or change allocation policy:
//! production heaps continue to allocate and resolve exclusively through
//! their existing closure store until a collector explicitly moves an object
//! here and publishes the returned value.

use super::*;

/// Owns the closure stores within an [`EvacuatedGeneration`].
#[derive(Debug)]
pub(in crate::eval::heap) struct EvacuatedClosureGeneration {
    arena: SharedFlatStoreArena,
    closures: FlatObjectStore<FlatClosurePayload>,
}

/// Returns whether one payload is admitted by the plain Node-thunk mover.
///
/// `physical_tail_free` must come from
/// [`FlatObjectStore::is_plain_relocation_source`], which checks both the
/// registry's tail witness and the exact registered object extent.
pub(in crate::eval::heap) fn plain_node_thunk_movable(
    payload: &FlatClosurePayload,
    physical_tail_free: bool,
) -> bool {
    let FlatClosurePayload::Thunk(thunk) = payload else {
        return false;
    };
    physical_tail_free
        && thunk.cell().state() == Ok(crate::eval::ThunkState::Suspended)
        && thunk.force_storage_mode() == EvalThunkForceStorageMode::Serial
        && thunk.state_arc_clone_count() == 0
        && matches!(thunk.kind(), EvalThunkKind::Node { .. })
        && thunk.with_scope_env().is_some_and(EvalWithEnv::is_empty)
        && thunk
            .scoped_global_env()
            .is_some_and(EvalScopedGlobalEnv::is_empty)
        && thunk.env().is_some_and(|env| env.flat_base().is_none())
}

impl EvacuatedClosureGeneration {
    /// Creates empty closure stores over the aggregate generation arena.
    pub(super) fn with_shared_arena(arena: SharedFlatStoreArena) -> Self {
        let closures = FlatObjectStore::with_shared_arena(
            arena.clone(),
            FlatKindSet::of(&[
                FlatObjectKind::Thunk,
                FlatObjectKind::Lambda,
                FlatObjectKind::Primop,
            ]),
        );
        Self { arena, closures }
    }

    /// Returns this generation's Candidate-C domain.
    pub(in crate::eval::heap) fn domain(&self) -> Option<crate::heap::ArenaDomainId> {
        self.arena.arena_domain_id()
    }

    /// Resolves a published thunk directly through the destination store.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a thunk in this
    /// generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_thunk(
        &self,
        value: Value,
    ) -> Result<&EvalThunk, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        self.get_thunk_ptr(ptr)
    }

    /// Resolves a raw thunk pointer through this generation.
    ///
    /// Returns `None` when `ptr` is not in the destination closure store, so
    /// the future heap router can retain nursery and record-table fallbacks.
    pub(in crate::eval::heap) fn thunk_probe(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<Result<&EvalThunk, EvalHeapError>> {
        match self.closures.resolve(ptr, FlatObjectKind::Thunk) {
            Ok(object) => Some(match object.payload() {
                FlatClosurePayload::Thunk(thunk) => Ok(thunk),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Thunk,
                    payload.tag(),
                    ptr,
                )),
            }),
            Err(FlatObjectError::KindMismatch { actual, .. }) => {
                Some(match self.closures.resolve(ptr, actual) {
                    Ok(object) if object.payload().is_retired() => {
                        Err(EvalHeapError::unknown(ValueTag::Thunk, ptr))
                    }
                    _ => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Thunk,
                        value_tag_for_flat_kind(actual),
                        ptr,
                    )),
                })
            }
            Err(_) => None,
        }
    }

    /// Resolves a raw thunk pointer through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is not a live ordinary thunk in
    /// this generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_thunk_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalThunk, EvalHeapError> {
        match self.thunk_probe(ptr) {
            Some(result) => result,
            None => Err(EvalHeapError::unknown(ValueTag::Thunk, ptr)),
        }
    }

    /// Resolves a published lambda directly through the destination store.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a lambda in this
    /// generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_lambda(
        &self,
        value: Value,
    ) -> Result<&EvalLambda, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        self.get_lambda_ptr(ptr)
    }

    /// Resolves a raw lambda pointer through this generation.
    ///
    /// Returns `None` when `ptr` is not in the destination closure store, so
    /// the heap router can retain nursery and record-table fallbacks.
    pub(in crate::eval::heap) fn lambda_probe(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<Result<&EvalLambda, EvalHeapError>> {
        match self.closures.resolve(ptr, FlatObjectKind::Lambda) {
            Ok(object) => Some(match object.payload() {
                FlatClosurePayload::Lambda(lambda) => Ok(lambda),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Lambda,
                    payload.tag(),
                    ptr,
                )),
            }),
            Err(FlatObjectError::KindMismatch { actual, .. }) => {
                Some(match self.closures.resolve(ptr, actual) {
                    Ok(object) if object.payload().is_retired() => {
                        Err(EvalHeapError::unknown(ValueTag::Lambda, ptr))
                    }
                    _ => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Lambda,
                        value_tag_for_flat_kind(actual),
                        ptr,
                    )),
                })
            }
            Err(_) => None,
        }
    }

    /// Resolves a raw lambda pointer through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is not a live lambda in this
    /// generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_lambda_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalLambda, EvalHeapError> {
        match self.lambda_probe(ptr) {
            Some(result) => result,
            None => Err(EvalHeapError::unknown(ValueTag::Lambda, ptr)),
        }
    }

    /// Resolves a published primop directly through the destination store.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a primop in this
    /// generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_primop(
        &self,
        value: Value,
    ) -> Result<&EvalPrimOp, EvalHeapError> {
        let ptr = value.as_primop_ptr().map_err(EvalHeapError::Value)?;
        self.get_primop_ptr(ptr)
    }

    /// Resolves a raw primop pointer through this generation.
    ///
    /// Returns `None` when `ptr` is not in the destination closure store, so
    /// the heap router can retain nursery and record-table fallbacks.
    pub(in crate::eval::heap) fn primop_probe(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<Result<&EvalPrimOp, EvalHeapError>> {
        match self.closures.resolve(ptr, FlatObjectKind::Primop) {
            Ok(object) => Some(match object.payload() {
                FlatClosurePayload::Primop(primop) => Ok(primop),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Primop,
                    payload.tag(),
                    ptr,
                )),
            }),
            Err(FlatObjectError::KindMismatch { actual, .. }) => {
                Some(match self.closures.resolve(ptr, actual) {
                    Ok(object) if object.payload().is_retired() => {
                        Err(EvalHeapError::unknown(ValueTag::Primop, ptr))
                    }
                    _ => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Primop,
                        value_tag_for_flat_kind(actual),
                        ptr,
                    )),
                })
            }
            Err(_) => None,
        }
    }

    /// Resolves a raw primop pointer through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is not a live primop in this
    /// generation or its payload/header kinds disagree.
    pub(in crate::eval::heap) fn get_primop_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalPrimOp, EvalHeapError> {
        match self.primop_probe(ptr) {
            Some(result) => result,
            None => Err(EvalHeapError::unknown(ValueTag::Primop, ptr)),
        }
    }

    fn value_for_primop(&self, ptr: NonNull<HeapObject>) -> Result<Value, EvalHeapError> {
        let domain = self
            .arena
            .arena_domain_id()
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated closure generation lost Candidate-C domain",
            })?;
        let index = self
            .arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated primop destination is outside its reservation",
            })?;
        Value::from_domain_index(ValueTag::Primop, domain, index).map_err(EvalHeapError::Value)
    }

    fn value_for_thunk(&self, ptr: NonNull<HeapObject>) -> Result<Value, EvalHeapError> {
        let domain = self
            .arena
            .arena_domain_id()
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated closure generation lost Candidate-C domain",
            })?;
        let index = self
            .arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated thunk destination is outside its reservation",
            })?;
        Value::from_domain_index(ValueTag::Thunk, domain, index).map_err(EvalHeapError::Value)
    }

    fn value_for_lambda(&self, ptr: NonNull<HeapObject>) -> Result<Value, EvalHeapError> {
        let domain = self
            .arena
            .arena_domain_id()
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated closure generation lost Candidate-C domain",
            })?;
        let index = self
            .arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated lambda destination is outside its reservation",
            })?;
        Value::from_domain_index(ValueTag::Lambda, domain, index).map_err(EvalHeapError::Value)
    }
}

impl EvalHeap {
    /// Installs an owned aggregate evacuated generation and its hot resolver.
    ///
    /// All resolver validation completes before either field is published.
    /// New allocations continue to use the nursery; installation only makes
    /// already-copied closure and permanent values resolvable through this
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] for a shared heap, an already-installed
    /// generation, or inconsistent Candidate-C reservation metadata.
    pub(in crate::eval::heap) fn install_evacuated_closure_generation(
        &mut self,
        generation: EvacuatedGeneration,
    ) -> Result<(), EvalHeapError> {
        let resolver = self.validate_evacuated_closure_generation_install(&generation, None)?;
        self.evacuated_generation = Some(generation);
        self.evacuated_serial_reservation = Some(resolver);
        Ok(())
    }

    /// Atomically installs an evacuated owner, resolver, and source alias directory.
    ///
    /// New allocations remain nursery-first. The directory currently
    /// canonicalizes only safe evaluator thunk/primop/lambda get, raw-pointer
    /// get, and clone paths. GC, JIT, FFI, and context-free `Value` access
    /// remain deliberately unwired, so this is not yet a production batch
    /// door.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] for a shared heap, an already-installed
    /// generation/directory, a heap without a Candidate-C nursery resolver, or
    /// directory domains inconsistent with the nursery and destination owner.
    pub(in crate::eval::heap) fn install_evacuated_closure_generation_with_forwarding(
        &mut self,
        generation: EvacuatedGeneration,
        forwarding: EvacuationForwardingDirectory,
    ) -> Result<(), EvalHeapError> {
        let resolver =
            self.validate_evacuated_closure_generation_install(&generation, Some(&forwarding))?;
        self.evacuated_generation = Some(generation);
        self.evacuated_serial_reservation = Some(resolver);
        self.evacuated_closure_forwarding = Some(forwarding);
        Ok(())
    }

    fn validate_evacuated_closure_generation_install(
        &self,
        generation: &EvacuatedGeneration,
        forwarding: Option<&EvacuationForwardingDirectory>,
    ) -> Result<SerialReservationResolver, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated aggregate generation requires a serial heap",
            });
        }
        if self.evacuated_serial_reservation.is_some()
            || self.evacuated_generation.is_some()
            || self.evacuated_closure_forwarding.is_some()
        {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated aggregate generation is already installed",
            });
        }
        let domain = generation.domain().ok_or(EvalHeapError::ShedRejected {
            address: 0,
            reason: "evacuated aggregate generation has no Candidate-C domain",
        })?;
        let base = crate::heap::reservation_base(domain).ok_or(EvalHeapError::ShedRejected {
            address: 0,
            reason: "evacuated closure generation domain is not registered",
        })?;
        let capacity = generation
            .reservation_capacity()
            .ok_or(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated aggregate generation has no reservation geometry",
            })?;
        let resolver = SerialReservationResolver {
            domain,
            base,
            capacity,
        };
        if let Some(forwarding) = forwarding {
            let source = self.serial_reservation.ok_or(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated closure forwarding requires a Candidate-C nursery",
            })?;
            if forwarding.source_domain() != source.domain {
                return Err(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "evacuated closure forwarding source domain is not the nursery",
                });
            }
            if forwarding.destination_domain() != resolver.domain {
                return Err(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "evacuated closure forwarding destination domain is not the installed generation",
                });
            }
        }
        Ok(resolver)
    }

    /// Moves and publishes one plain suspended Node thunk into `destination`.
    ///
    /// This default-off primitive admits only an inline, tail-free thunk whose
    /// force state is still suspended, whose storage is ordinary serial
    /// storage, and whose lexical environment does not contain an
    /// owner-relative flat capture. Shared payloads, dynamic captures, and
    /// synthetic thunk kinds require the broader root and edge publication
    /// transaction.
    ///
    /// Shared [`EvalFrame`] identities in an ordinary lexical environment move
    /// with the payload unchanged. Passing a generation explicitly is the
    /// installation gate; ordinary allocation and resolution do not consult it.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an eligible live flat
    /// thunk, destination allocation fails, the stores share backing, or
    /// publication metadata is inconsistent with the destination reservation.
    pub(in crate::eval::heap) fn relocate_plain_thunk_to_generation(
        &mut self,
        destination: &mut EvacuatedClosureGeneration,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated closure generation requires a serial heap",
            });
        }
        let ptr = source.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        if !self.worker_region_mark_stack.is_empty() {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "closure evacuation requires no active worker region",
            });
        }
        let physical_tail_free = self
            .flat_closures
            .is_plain_relocation_source(ptr, FlatObjectKind::Thunk)
            .map_err(|error| self.closure_resolution_error(ValueTag::Thunk, ptr, error))?;
        match self.flat_closures.resolve(ptr, FlatObjectKind::Thunk) {
            Ok(object) => match object.payload() {
                payload if plain_node_thunk_movable(payload, physical_tail_free) => {}
                FlatClosurePayload::Thunk(_) => {
                    return Err(EvalHeapError::ShedRejected {
                        address: ptr.as_ptr() as usize,
                        reason: "plain thunk evacuation requires a suspended serial Node thunk without dynamic or inline-flat captures",
                    });
                }
                FlatClosurePayload::SharedThunk(_) => {
                    return Err(EvalHeapError::ShedRejected {
                        address: ptr.as_ptr() as usize,
                        reason: "plain thunk evacuation slice requires an unshared payload",
                    });
                }
                payload => {
                    return Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Thunk,
                        payload.tag(),
                        ptr,
                    ));
                }
            },
            Err(error) => {
                return Err(self.closure_resolution_error(ValueTag::Thunk, ptr, error));
            }
        }

        let relocation = self
            .flat_closures
            .relocate_plain_to_with(
                &mut destination.closures,
                ptr,
                FlatObjectKind::Thunk,
                |payload| {
                    debug_assert!(matches!(payload, FlatClosurePayload::Thunk(_)));
                    // The admitted Node payload owns no direct Value edge.
                    // Shared frame slots are rewritten by the global pass.
                },
            )
            .map_err(|error| self.closure_resolution_error(ValueTag::Thunk, ptr, error))?;
        self.flat_closures_retired = self.flat_closures_retired.saturating_add(1);
        destination.value_for_thunk(relocation.destination.ptr)
    }

    /// Moves and publishes one plain primop into `destination`.
    ///
    /// `rewrite` is applied to every captured primop argument during the
    /// mover's allocation-free commit. The source must be an ordinary flat
    /// primop without inline tail storage. Passing a generation explicitly is
    /// the installation gate; ordinary allocation and resolution do not
    /// consult it.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not a live flat primop,
    /// destination allocation fails, the stores share backing, or publication
    /// metadata is inconsistent with the destination reservation.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`; see
    /// [`FlatObjectStore::relocate_plain_to_with`] for its unwind contract.
    pub(in crate::eval::heap) fn relocate_plain_primop_to_generation(
        &mut self,
        destination: &mut EvacuatedClosureGeneration,
        source: Value,
        mut rewrite: impl FnMut(Value) -> Value,
    ) -> Result<Value, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated closure generation requires a serial heap",
            });
        }
        let ptr = source.as_primop_ptr().map_err(EvalHeapError::Value)?;
        if !self.worker_region_mark_stack.is_empty() {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "closure evacuation requires no active worker region",
            });
        }
        match self.flat_closures.resolve(ptr, FlatObjectKind::Primop) {
            Ok(object) if matches!(object.payload(), FlatClosurePayload::Primop(_)) => {}
            Ok(object) => {
                return Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Primop,
                    object.payload().tag(),
                    ptr,
                ));
            }
            Err(error) => {
                return Err(self.closure_resolution_error(ValueTag::Primop, ptr, error));
            }
        }

        let relocation = self
            .flat_closures
            .relocate_plain_to_with(
                &mut destination.closures,
                ptr,
                FlatObjectKind::Primop,
                |payload| {
                    if let FlatClosurePayload::Primop(primop) = payload {
                        for argument in &mut primop.args {
                            argument.value = rewrite(argument.value);
                        }
                    }
                },
            )
            .map_err(|error| self.closure_resolution_error(ValueTag::Primop, ptr, error))?;
        self.flat_closures_retired = self.flat_closures_retired.saturating_add(1);
        destination.value_for_primop(relocation.destination.ptr)
    }

    /// Moves and publishes one plain tail-free lambda into `destination`.
    ///
    /// The V1 lambda shape has no directly owned `Value` fields to rewrite.
    /// Lexical values belong to shared [`EvalFrame`] objects and are forwarded
    /// once per distinct frame by the global publication phase. Dynamic
    /// captures and inline flat captures are rejected here because their
    /// persistent or owner-relative storage requires that broader transaction.
    /// The lambda payload keeps its existing shared frame identities.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not a live flat lambda, has
    /// dynamic or inline-flat captures, carries an inline allocation tail,
    /// destination allocation fails, the stores share backing, or publication
    /// metadata disagrees with the destination reservation.
    pub(in crate::eval::heap) fn relocate_plain_lambda_to_generation(
        &mut self,
        destination: &mut EvacuatedClosureGeneration,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuated closure generation requires a serial heap",
            });
        }
        let ptr = source.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        if !self.worker_region_mark_stack.is_empty() {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "closure evacuation requires no active worker region",
            });
        }
        match self.flat_closures.resolve(ptr, FlatObjectKind::Lambda) {
            Ok(object) => match object.payload() {
                FlatClosurePayload::Lambda(lambda)
                    if lambda.with_scope_env().is_empty()
                        && lambda.scoped_global_env().is_empty()
                        && lambda.env().flat_base().is_none() => {}
                FlatClosurePayload::Lambda(_) => {
                    return Err(EvalHeapError::ShedRejected {
                        address: ptr.as_ptr() as usize,
                        reason: "plain lambda evacuation requires no dynamic or inline-flat captures",
                    });
                }
                payload => {
                    return Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Lambda,
                        payload.tag(),
                        ptr,
                    ));
                }
            },
            Err(error) => {
                return Err(self.closure_resolution_error(ValueTag::Lambda, ptr, error));
            }
        }

        let relocation = self
            .flat_closures
            .relocate_plain_to_with(
                &mut destination.closures,
                ptr,
                FlatObjectKind::Lambda,
                |payload| {
                    debug_assert!(matches!(payload, FlatClosurePayload::Lambda(_)));
                    // This V1 payload has no directly owned Value edge. Shared
                    // frame slots are rewritten by the global publication pass.
                },
            )
            .map_err(|error| self.closure_resolution_error(ValueTag::Lambda, ptr, error))?;
        self.flat_closures_retired = self.flat_closures_retired.saturating_add(1);
        destination.value_for_lambda(relocation.destination.ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::heap::evacuation_forwarding::EvacuationForwardingDirectoryBuilder;
    use crate::eval::{EvalFrame, EvalWithScope};
    use std::sync::Arc;

    #[test]
    fn plain_tail_free_node_thunk_moves_with_code_env_and_forwarding_identity() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let frame = EvalFrame::new(1).expect("frame allocates");
        frame.set(0, Value::int(17)).expect("frame slot stores");
        let env = EvalEnv::capture(&[Arc::clone(&frame)]).expect("lexical env captures");
        let source = source_heap
            .alloc_thunk(EvalThunk::with_env(
                EvalModuleId::new(2),
                IrId::new(3),
                env.clone(),
            ))
            .expect("source thunk allocates");
        let source_domain = source
            .word()
            .arena_domain()
            .expect("source thunk has a Candidate-C domain");
        let destination_domain = destination
            .domain()
            .expect("destination has a Candidate-C domain");
        let source_index = source
            .word()
            .arena_index()
            .expect("source thunk has an arena index");
        let source_ptr = source.as_thunk_ptr().expect("source thunk has a pointer");

        let moved = source_heap
            .relocate_plain_thunk_to_generation(destination.closures_mut(), source)
            .expect("plain Node thunk relocates");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        let moved_ptr = moved.as_thunk_ptr().expect("moved thunk has a pointer");
        let thunk = destination
            .closures()
            .get_thunk(moved)
            .expect("destination resolves moved thunk");
        assert_eq!(
            thunk.body_ref(),
            Some(EvalNodeRef::new(EvalModuleId::new(2), IrId::new(3)))
        );
        assert!(
            thunk.env().is_some_and(|moved_env| moved_env.raw_eq(&env)),
            "movement preserves the lexical environment backing"
        );
        assert_eq!(thunk.cell().state(), Ok(crate::eval::ThunkState::Suspended));
        assert_eq!(
            destination
                .closures()
                .get_thunk_ptr(moved_ptr)
                .expect("raw destination pointer resolves")
                .body(),
            Some(IrId::new(3))
        );
        assert!(
            source_heap.get_thunk(source).is_err(),
            "movement retires the old source"
        );
        assert_eq!(source_heap.flat_closures_retired, 1);

        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 1)
                .expect("forwarding directory reserves");
        builder
            .push(
                source_index,
                moved
                    .word()
                    .arena_index()
                    .expect("moved thunk has a destination index"),
            )
            .expect("forwarding entry appends");
        let forwarding = builder.finish().expect("forwarding directory finalizes");
        assert!(
            forwarding
                .translate(source, ValueTag::Thunk)
                .is_some_and(|translated| translated.raw_eq(moved)),
            "the old thunk identity forwards exactly to the moved identity"
        );
        source_heap
            .install_evacuated_closure_generation_with_forwarding(destination, forwarding)
            .expect("owner, resolver, and forwarding directory install together");
        assert_eq!(
            source_heap
                .get_thunk(source)
                .expect("old thunk word forwards")
                .body_ref(),
            Some(EvalNodeRef::new(EvalModuleId::new(2), IrId::new(3)))
        );
        assert_eq!(
            source_heap
                .get_thunk_ptr(source_ptr)
                .expect("old thunk pointer forwards")
                .body(),
            Some(IrId::new(3))
        );
        assert_eq!(
            source_heap
                .get_thunk(moved)
                .expect("direct moved thunk word resolves")
                .body(),
            Some(IrId::new(3))
        );
        assert_eq!(
            source_heap
                .get_thunk_ptr(moved_ptr)
                .expect("direct moved thunk pointer resolves")
                .body(),
            Some(IrId::new(3))
        );
        assert_eq!(
            source_heap
                .clone_thunk(source)
                .expect("old thunk word clones through forwarding")
                .body(),
            Some(IrId::new(3))
        );
        let fresh = source_heap
            .alloc_thunk(EvalThunk::new(IrId::new(4)))
            .expect("post-install nursery thunk allocates");
        assert_eq!(
            fresh.word().arena_domain(),
            Some(source_domain),
            "installation leaves new thunk allocation nursery-first"
        );
        assert_eq!(
            source_heap
                .get_thunk(fresh)
                .expect("fresh nursery thunk probes before destination routing")
                .body(),
            Some(IrId::new(4))
        );
    }

    #[test]
    fn synthetic_and_dynamic_thunks_are_rejected_before_source_mutation() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let synthetic = source_heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(1),
                Span::new(2, 3),
                Value::int(4),
                EvalModuleId::ROOT,
                IrId::new(5),
                Value::int(6),
            ))
            .expect("synthetic thunk allocates");
        assert!(
            source_heap
                .relocate_plain_thunk_to_generation(destination.closures_mut(), synthetic)
                .is_err(),
            "synthetic Value edges require the global rewrite transaction"
        );
        assert!(matches!(
            source_heap
                .get_thunk(synthetic)
                .expect("synthetic rejection preserves source")
                .kind(),
            EvalThunkKind::Apply { .. }
        ));

        let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
            EvalModuleId::ROOT,
            IrId::new(7),
            Value::int(8),
        )])
        .expect("dynamic scope captures");
        let dynamic = source_heap
            .alloc_thunk(EvalThunk::with_captures(
                EvalModuleId::ROOT,
                IrId::new(9),
                EvalEnv::default(),
                with_env,
                EvalScopedGlobalEnv::default(),
            ))
            .expect("dynamic thunk allocates");
        assert!(
            source_heap
                .relocate_plain_thunk_to_generation(destination.closures_mut(), dynamic)
                .is_err(),
            "dynamic captures require the global publication transaction"
        );
        assert_eq!(
            source_heap
                .get_thunk(dynamic)
                .expect("dynamic rejection preserves source")
                .body(),
            Some(IrId::new(9))
        );
        assert_eq!(source_heap.flat_closures_retired, 0);
    }

    #[test]
    fn shared_thunk_payload_is_rejected_before_source_mutation() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let source = source_heap
            .alloc_thunk(EvalThunk::new(IrId::new(11)))
            .expect("source thunk allocates");
        let ptr = source.as_thunk_ptr().expect("source thunk has a pointer");
        let shared = source_heap
            .share_thunk_from_ptr(ptr, source)
            .expect("source thunk shares");

        assert!(
            source_heap
                .relocate_plain_thunk_to_generation(destination.closures_mut(), source)
                .is_err(),
            "shared payload identity cannot move in the plain slice"
        );
        assert_eq!(
            source_heap
                .get_thunk(source)
                .expect("shared rejection preserves source")
                .body(),
            Some(IrId::new(11))
        );
        assert_eq!(source_heap.flat_closures_retired, 0);
        drop(shared);
    }

    #[test]
    fn inline_flat_capture_thunk_is_rejected_before_source_mutation() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(13));
        let mut capture = EvalFlatCaptureBuffer::new(site, 1);
        capture.push(Value::int(14)).expect("capture value fits");
        let source = source_heap
            .alloc_thunk_with_flat_capture(EvalThunk::new(IrId::new(15)), Some(capture.finish()))
            .expect("flat-capture thunk allocates")
            .0;

        assert!(
            source_heap
                .relocate_plain_thunk_to_generation(destination.closures_mut(), source)
                .is_err(),
            "owner-relative flat capture cannot move in the plain slice"
        );
        let source_thunk = source_heap
            .get_thunk(source)
            .expect("flat-capture rejection preserves source");
        assert_eq!(source_thunk.body(), Some(IrId::new(15)));
        assert!(
            source_thunk
                .env()
                .is_some_and(|env| env.flat_base().is_some()),
            "the source retains its owner-relative flat capture"
        );
        assert_eq!(source_heap.flat_closures_retired, 0);
    }

    #[test]
    fn plain_primop_moves_to_independent_generation_and_publishes_rewritten_value() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        assert_ne!(
            source_heap.flat_arena.arena_domain_id(),
            destination.domain(),
            "the evacuated generation owns an independent reservation"
        );

        let argument = EvalPrimOpArg::new(IrId::new(3), Span::new(4, 5), Value::int(7));
        let source = source_heap
            .alloc_primop(EvalPrimOp::with_args(Symbol::new(9), vec![argument]))
            .expect("source primop allocates");
        let moved = source_heap
            .relocate_plain_primop_to_generation(destination.closures_mut(), source, |value| {
                if value.raw_eq(Value::int(7)) {
                    Value::int(11)
                } else {
                    value
                }
            })
            .expect("plain primop relocates and publishes");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        let primop = destination
            .closures()
            .get_primop(moved)
            .expect("destination store resolves the moved value");
        assert_eq!(primop.symbol(), Symbol::new(9));
        assert_eq!(primop.args().len(), 1);
        assert!(primop.args()[0].value().raw_eq(Value::int(11)));
        assert!(
            source_heap.get_primop(source).is_err(),
            "the source store retired the old address"
        );
        assert_eq!(
            source_heap.flat_closures_retired, 1,
            "movement participates in the region-pop retirement interlock"
        );
        assert!(
            source_heap.get_primop(moved).is_err(),
            "the destination stays uninstalled in ordinary heap routing"
        );
        let moved_ptr = moved
            .as_primop_ptr()
            .expect("published moved value has a raw pointer");
        source_heap
            .install_evacuated_closure_generation(destination)
            .expect("owner and resolver install together");
        assert_eq!(
            source_heap
                .get_primop(moved)
                .expect("ordinary value resolution routes to destination")
                .symbol(),
            Symbol::new(9)
        );
        assert!(
            source_heap
                .get_primop_ptr(moved_ptr)
                .expect("raw-pointer resolution routes to destination")
                .args()[0]
                .value()
                .raw_eq(Value::int(11))
        );
        assert!(
            source_heap
                .clone_primop(moved)
                .expect("clone routing reaches destination")
                .raw_eq(
                    source_heap
                        .get_primop(moved)
                        .expect("installed destination stays resolvable")
                )
        );
        assert!(
            source_heap.get_primop(source).is_err(),
            "the retired source remains unknown after installation"
        );
    }

    #[test]
    fn plain_tail_free_lambda_moves_and_routes_through_installed_generation() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let source = source_heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(3),
                IrId::new(4),
                FrameId::new(5),
                EvalEnv::default(),
            ))
            .expect("source lambda allocates");
        let moved = source_heap
            .relocate_plain_lambda_to_generation(destination.closures_mut(), source)
            .expect("plain lambda relocates and publishes");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        let lambda = destination
            .closures()
            .get_lambda(moved)
            .expect("destination resolves the moved lambda");
        assert_eq!(lambda.pattern(), IrId::new(3));
        assert_eq!(lambda.body(), IrId::new(4));
        assert_eq!(lambda.frame(), FrameId::new(5));
        assert!(
            lambda.env().is_empty(),
            "the V1 routing fixture has no frame edges to publish"
        );
        assert!(
            source_heap.get_lambda(source).is_err(),
            "the source store retired the old address"
        );
        assert_eq!(source_heap.flat_closures_retired, 1);
        assert!(
            source_heap.get_lambda(moved).is_err(),
            "the destination remains private until installation"
        );

        let moved_ptr = moved
            .as_lambda_ptr()
            .expect("published moved value has a raw pointer");
        source_heap
            .install_evacuated_closure_generation(destination)
            .expect("owner and resolver install together");
        assert_eq!(
            source_heap
                .get_lambda(moved)
                .expect("value resolution routes to destination")
                .body(),
            IrId::new(4)
        );
        assert_eq!(
            source_heap
                .get_lambda_ptr(moved_ptr)
                .expect("raw-pointer resolution routes to destination")
                .pattern(),
            IrId::new(3)
        );
        assert!(
            source_heap
                .clone_lambda(moved)
                .expect("clone routing reaches destination")
                .raw_eq(
                    source_heap
                        .get_lambda(moved)
                        .expect("installed destination remains resolvable")
                )
        );
        assert!(
            source_heap.get_lambda(source).is_err(),
            "the retired source remains unknown after installation"
        );
        let fresh = source_heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(6),
                IrId::new(7),
                FrameId::new(8),
                EvalEnv::default(),
            ))
            .expect("post-install lambda allocates");
        assert_eq!(
            fresh.word().arena_domain(),
            source.word().arena_domain(),
            "installation does not redirect new allocations away from the nursery"
        );
        assert_ne!(fresh.word().arena_domain(), moved.word().arena_domain());
        assert_eq!(
            source_heap
                .get_lambda(fresh)
                .expect("fresh nursery lambda remains routable")
                .body(),
            IrId::new(7)
        );
    }

    #[test]
    fn installed_forwarding_resolves_old_primop_and_lambda_words_and_pointers() {
        enum PlannedClosure {
            Primop(Value),
            Lambda(Value),
        }

        impl PlannedClosure {
            fn value(&self) -> Value {
                match self {
                    Self::Primop(value) | Self::Lambda(value) => *value,
                }
            }
        }

        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let primop = source_heap
            .alloc_primop(EvalPrimOp::with_args(
                Symbol::new(9),
                vec![EvalPrimOpArg::new(
                    IrId::new(3),
                    Span::new(4, 5),
                    Value::int(7),
                )],
            ))
            .expect("source primop allocates");
        let lambda = source_heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(10),
                IrId::new(11),
                FrameId::new(12),
                EvalEnv::default(),
            ))
            .expect("source lambda allocates");
        let primop_ptr = primop
            .as_primop_ptr()
            .expect("source primop has a raw pointer");
        let lambda_ptr = lambda
            .as_lambda_ptr()
            .expect("source lambda has a raw pointer");
        let source_domain = primop
            .word()
            .arena_domain()
            .expect("source primop has a Candidate-C domain");
        assert_eq!(lambda.word().arena_domain(), Some(source_domain));
        let destination_domain = destination
            .domain()
            .expect("destination has a Candidate-C domain");
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 2)
                .expect("forwarding directory reserves before movement");
        let mut planned = vec![
            PlannedClosure::Primop(primop),
            PlannedClosure::Lambda(lambda),
        ];
        planned.sort_unstable_by_key(|closure| {
            closure
                .value()
                .word()
                .arena_index()
                .expect("planned closure has an arena index")
        });

        let mut moved_primop = None;
        let mut moved_lambda = None;
        for closure in planned {
            let source = closure.value();
            let source_index = source
                .word()
                .arena_index()
                .expect("planned source has an arena index");
            let append = builder
                .prepare_append(source_index)
                .expect("source ordering validates before retirement");
            let moved = match closure {
                PlannedClosure::Primop(_) => {
                    let moved = source_heap
                        .relocate_plain_primop_to_generation(
                            destination.closures_mut(),
                            source,
                            |value| value,
                        )
                        .expect("plain primop relocates");
                    moved_primop = Some(moved);
                    moved
                }
                PlannedClosure::Lambda(_) => {
                    let moved = source_heap
                        .relocate_plain_lambda_to_generation(destination.closures_mut(), source)
                        .expect("plain lambda relocates");
                    moved_lambda = Some(moved);
                    moved
                }
            };
            append.commit(
                moved
                    .word()
                    .arena_index()
                    .expect("moved closure has a destination index"),
            );
        }
        let forwarding = builder
            .finish()
            .expect("complete forwarding directory finalizes");
        let moved_primop = moved_primop.expect("primop participated in the plan");
        let moved_lambda = moved_lambda.expect("lambda participated in the plan");
        source_heap
            .install_evacuated_closure_generation_with_forwarding(destination, forwarding)
            .expect("owner, resolver, and directory install atomically");

        assert_eq!(
            source_heap
                .get_primop(primop)
                .expect("old primop word forwards")
                .symbol(),
            Symbol::new(9)
        );
        assert_eq!(
            source_heap
                .get_primop_ptr(primop_ptr)
                .expect("old primop pointer forwards")
                .args()
                .len(),
            1
        );
        assert!(
            source_heap
                .clone_primop(primop)
                .expect("old primop word clones through forwarding")
                .raw_eq(
                    source_heap
                        .get_primop(moved_primop)
                        .expect("direct moved primop remains routable")
                )
        );
        assert_eq!(
            source_heap
                .get_lambda(lambda)
                .expect("old lambda word forwards")
                .body(),
            IrId::new(11)
        );
        assert_eq!(
            source_heap
                .get_lambda_ptr(lambda_ptr)
                .expect("old lambda pointer forwards")
                .pattern(),
            IrId::new(10)
        );
        assert!(
            source_heap
                .clone_lambda(lambda)
                .expect("old lambda word clones through forwarding")
                .raw_eq(
                    source_heap
                        .get_lambda(moved_lambda)
                        .expect("direct moved lambda remains routable")
                )
        );

        let fresh = source_heap
            .alloc_primop(EvalPrimOp::new(Symbol::new(13)))
            .expect("post-install primop allocates");
        assert_eq!(
            fresh.word().arena_domain(),
            Some(source_domain),
            "forwarding installation leaves allocation nursery-first"
        );
        assert_eq!(
            source_heap
                .get_primop(fresh)
                .expect("unmoved nursery object probes before alias lookup")
                .symbol(),
            Symbol::new(13)
        );
    }

    #[test]
    fn forwarding_install_rejects_domain_mismatches_without_partial_publication() {
        let mut source_heap = EvalHeap::new();
        let Some(destination) = EvacuatedGeneration::new() else {
            return;
        };
        let Some(foreign) = EvacuatedGeneration::new() else {
            return;
        };
        let source_domain = source_heap
            .serial_reservation
            .expect("Candidate-C heap has a nursery resolver")
            .domain;
        let destination_domain = destination
            .domain()
            .expect("destination has a Candidate-C domain");
        let foreign_domain = foreign
            .domain()
            .expect("foreign generation has a Candidate-C domain");
        let wrong_source =
            EvacuationForwardingDirectoryBuilder::try_new(foreign_domain, destination_domain, 0)
                .expect("mismatched directory constructs")
                .finish()
                .expect("empty validation fixture finalizes");

        assert!(
            source_heap
                .install_evacuated_closure_generation_with_forwarding(destination, wrong_source,)
                .is_err(),
            "directory source must be this heap's nursery"
        );
        assert!(source_heap.evacuated_serial_reservation.is_none());
        assert!(source_heap.evacuated_generation.is_none());
        assert!(source_heap.evacuated_closure_forwarding.is_none());

        let Some(destination) = EvacuatedGeneration::new() else {
            return;
        };
        let Some(foreign) = EvacuatedGeneration::new() else {
            return;
        };
        let wrong_destination = EvacuationForwardingDirectoryBuilder::try_new(
            source_domain,
            foreign
                .domain()
                .expect("foreign generation has a Candidate-C domain"),
            0,
        )
        .expect("mismatched directory constructs")
        .finish()
        .expect("empty validation fixture finalizes");

        assert!(
            source_heap
                .install_evacuated_closure_generation_with_forwarding(
                    destination,
                    wrong_destination,
                )
                .is_err(),
            "directory destination must be the installed owner"
        );
        assert!(source_heap.evacuated_serial_reservation.is_none());
        assert!(source_heap.evacuated_generation.is_none());
        assert!(source_heap.evacuated_closure_forwarding.is_none());
    }

    #[test]
    fn lambda_with_dynamic_capture_is_rejected_before_source_mutation() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
            EvalModuleId::ROOT,
            IrId::new(9),
            Value::int(23),
        )])
        .expect("dynamic scope captures");
        let source = source_heap
            .alloc_lambda(EvalLambda::with_captures(
                EvalModuleId::ROOT,
                IrId::new(10),
                IrId::new(11),
                FrameId::new(12),
                EvalEnv::default(),
                with_env,
                EvalScopedGlobalEnv::default(),
            ))
            .expect("source lambda allocates");

        assert!(
            source_heap
                .relocate_plain_lambda_to_generation(destination.closures_mut(), source)
                .is_err(),
            "dynamic captures require the global publication transaction"
        );
        assert_eq!(
            source_heap
                .get_lambda(source)
                .expect("rejection leaves source payload intact")
                .body(),
            IrId::new(11)
        );
        assert_eq!(
            source_heap.flat_closures_retired, 0,
            "rejection cannot enter the relocation commit"
        );
    }
}
