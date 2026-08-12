//! Tree-walk evaluator tests: attrs 1.

use crate::cache::{
    DemandCacheKey, DemandDependencyGroup, DemandNodeId, PERSIST_NODE_METADATA_INDEX_ENTRY_LEN,
    PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN, PersistNodeTraceLogEntry,
};

use super::*;

mod basic;
mod captured_composites_a;
mod captured_composites_b;
mod captured_scalars;
mod closed_literal_payloads;
mod force_cache_ambient;
mod force_cache_effectful;
mod force_cache_file_payloads_a;
mod force_cache_file_payloads_b;
mod force_cache_identity;
mod force_cache_imports;
mod force_cache_persistent_demand_a;
mod force_cache_persistent_demand_b;
mod force_cache_persistent_effectful_inputs;
mod force_cache_persistent_file_inputs;
mod force_cache_persistent_imports;
mod force_cache_persistent_metadata_inputs;
mod force_cache_persistent_uncacheable_inputs;
mod force_cache_search_path_policy;
mod force_cache_synthetic_builtins;
mod materialized_captures;
mod payload_rehydration;
mod positioned_payloads;

fn force_attr_a(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol) -> Value {
    force_attr(evaluator, ir, a, "a")
}

fn assert_source_order_attrset_ints(evaluator: &TreeWalk, value: Value, expected: &[(&[u8], i64)]) {
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("forced value is an attrset");
    assert_ne!(
        attrs.source_order(),
        attrs.iteration_order(),
        "attrset must preserve source-order metadata"
    );
    let source_order: Vec<_> = attrs
        .iter_source_order()
        .map(|entry| {
            (
                evaluator
                    .symbols
                    .resolve(entry.key)
                    .expect("entry symbol resolves")
                    .to_vec(),
                entry.value.as_int().expect("entry value is an int"),
            )
        })
        .collect();
    let expected = expected
        .iter()
        .map(|(name, value)| (name.to_vec(), *value))
        .collect::<Vec<_>>();
    assert_eq!(source_order, expected);
}

fn force_attr_a_string(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol, expected: &[u8]) {
    let value = force_attr_a(evaluator, ir, a);
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("forced value is a string");
    assert_eq!(string.bytes(), expected);
}

fn force_attr_a_attrs_strings(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
    expected: &[(&[u8], &[u8])],
) {
    let value = force_attr_a(evaluator, ir, a);
    let symbols = expected
        .iter()
        .map(|(name, _)| evaluator.symbols.intern(name).expect("symbol interns"))
        .collect::<Vec<_>>();
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("forced value is an attrset");
    assert_eq!(attrs.len(), expected.len());
    for ((name, expected_value), symbol) in expected.iter().zip(symbols) {
        let value = attrs
            .get(symbol)
            .unwrap_or_else(|| panic!("{} exists", String::from_utf8_lossy(name)));
        let string = evaluator
            .heap()
            .get_string(value)
            .expect("attr value is a string");
        assert_eq!(string.bytes(), *expected_value);
    }
}

trait ForceAdmittedValue {
    fn force_admitted_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError>;
}

impl ForceAdmittedValue for TreeWalk {
    fn force_admitted_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let subject = {
            let thunk = self.heap().get_thunk(value).ok();
            thunk.and_then(|thunk| {
                self.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, id), thunk)
            })
        };
        if let Some(subject) = subject {
            self.record_force_cache_memoization_demand(&subject);
            self.record_force_cache_memoization_demand(&subject);
        }
        TreeWalk::force_value(self, id, span, value)
    }
}

fn force_attr(evaluator: &mut TreeWalk, ir: &Ir, attr: Symbol, label: &str) -> Value {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(attr).unwrap_or_else(|| panic!("{label} exists"))
    };
    evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds")
}

fn seed_prior_persistent_demand_for_attr(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    attr: Symbol,
    persist_root: &std::path::Path,
    label: &str,
) -> Value {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(attr).unwrap_or_else(|| panic!("{label} exists"))
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .unwrap_or_else(|_| panic!("{label} remains a suspended thunk"));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .unwrap_or_else(|| panic!("{label} force-cache subject builds"))
    };
    let identity = subject
        .metadata_identity
        .unwrap_or_else(|| panic!("{label} has persistent metadata identity"));
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    PersistCache::open(persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    thunk_value
}
fn cache_nodes_with_dependencies(cache: &EvalCache) -> usize {
    (0..cache.len())
        .filter(|index| {
            let raw = u32::try_from(*index).expect("test graph has u32-addressable nodes");
            !cache
                .graph()
                .node(crate::cache::DemandNodeId::new(raw))
                .expect("node exists")
                .dependencies()
                .is_empty()
        })
        .count()
}

fn assert_force_cache_impure_edges_match_trace(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    expected_owner: DemandCacheKey,
    expected_trace: &[ImpureInputFingerprint],
) {
    assert!(
        !expected_trace.is_empty(),
        "edge-exactness assertions require at least one input leaf"
    );
    let runtime = runtime.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let graph = cache.graph();
    let expected_owner = graph
        .node_id_for_key(expected_owner)
        .expect("forced expression node exists");
    let expected_leaf_nodes = expected_trace
        .iter()
        .map(|fingerprint| {
            let fingerprint = fingerprint
                .as_cacheable()
                .expect("expected trace is cacheable");
            let key = DemandCacheKey::for_impure_input(fingerprint.identity().hash());
            graph.node_id_for_key(key).unwrap_or_else(|| {
                panic!(
                    "cache graph contains no leaf node for {:?} input",
                    fingerprint.kind()
                )
            })
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        expected_leaf_nodes.len(),
        expected_trace.len(),
        "each observed input fingerprint should map to one distinct graph leaf"
    );

    let impure_edge_owners = (0..cache.len())
        .filter_map(|index| {
            let raw = u32::try_from(index).expect("test graph has u32-addressable nodes");
            let node = DemandNodeId::new(raw);
            let dependencies = graph
                .node(node)
                .expect("node exists")
                .dependencies_in_group(DemandDependencyGroup::ImpureInput)?;
            (!dependencies.is_empty()).then(|| (node, dependencies.clone()))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        impure_edge_owners.len(),
        1,
        "a single forced attr thunk should own the impure-input edge group"
    );
    let (owner, dependencies) = impure_edge_owners[0].clone();
    assert_eq!(
        owner, expected_owner,
        "the force-cache expression node should own the impure-input edge group"
    );
    assert_eq!(
        dependencies, expected_leaf_nodes,
        "the forced attr thunk should depend on exactly the observed input leaves"
    );
    for dependency in dependencies {
        assert!(
            graph
                .node(dependency)
                .expect("dependency exists")
                .dependents()
                .contains(&owner),
            "input leaf should record the forced expression as a reverse dependent"
        );
    }
}

fn force_attr_a_with_impure_observation_key(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
) -> (Value, DemandCacheKey) {
    let (forced, subject) = force_attr_a_with_force_cache_subject(evaluator, ir, a);
    let key = DemandCacheKey::for_free_vars(
        subject
            .impure_observation_identity
            .expect("a has an impure observation identity"),
        subject.free_var_value_hashes.iter().copied(),
    )
    .expect("a force-cache impure observation key builds");
    (forced, key)
}

fn force_attr_a_with_impure_observation_subject(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
) -> (Value, ForceCacheSubject) {
    force_attr_a_with_force_cache_subject(evaluator, ir, a)
}

fn force_attr_a_with_force_cache_subject(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
) -> (Value, ForceCacheSubject) {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("a force-cache subject builds")
    };
    evaluator.record_force_cache_memoization_demand(&subject);
    evaluator.record_force_cache_memoization_demand(&subject);
    let forced = TreeWalk::force_value(evaluator, ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    (forced, subject)
}

fn persistent_path_exists_trace_payload(path: &[u8], exists: bool) -> PersistNodeTracePayload {
    let input =
        ImpureInputFingerprint::path_exists(path, exists).expect("pathExists fingerprint builds");
    PersistNodeTracePayload::from_impure_trace([&input]).expect("trace payload builds")
}

fn persistent_empty_trace_payload() -> PersistNodeTracePayload {
    PersistNodeTracePayload::from_impure_trace(std::iter::empty::<&ImpureInputFingerprint>())
        .expect("empty trace payload builds")
}
fn opaque_capture_context(path: &[u8]) -> StringContext {
    StringContext::singleton(
        ContextElement::opaque_path(path.to_vec()).expect("opaque context path is valid"),
    )
    .expect("context allocates")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LazyElementListCaptureState {
    DirectList,
    ForcedThunk,
    SuspendedThunk,
}

fn lazy_element_list_capture_state(
    evaluator: &TreeWalk,
    ir: &Ir,
    value: Value,
) -> Option<LazyElementListCaptureState> {
    fn list_has_suspended_element(evaluator: &TreeWalk, value: Value) -> bool {
        let Ok(list) = evaluator.heap().get_list(value) else {
            return false;
        };
        let Some(element) = list.get(0) else {
            return false;
        };
        evaluator
            .heap()
            .get_thunk(element)
            .map(|element| element.cell().state() == Ok(ThunkState::Suspended))
            .unwrap_or(false)
    }

    if list_has_suspended_element(evaluator, value) {
        return Some(LazyElementListCaptureState::DirectList);
    }
    let Ok(thunk) = evaluator.heap().get_thunk(value) else {
        return None;
    };
    match thunk.cell().cached_value() {
        Ok(Some(cached)) if list_has_suspended_element(evaluator, cached) => {
            Some(LazyElementListCaptureState::ForcedThunk)
        }
        Ok(None) => (thunk.cell().state() == Ok(ThunkState::Suspended)
            && thunk
                .body()
                .and_then(|body| ir.arena.node(body))
                .map(|node| node.kind == IrKind::List)
                .unwrap_or(false))
        .then_some(LazyElementListCaptureState::SuspendedThunk),
        Ok(Some(_)) | Err(_) => None,
    }
}

fn subtree_contains_upval_capture(ir: &Ir, root: IrId) -> bool {
    let mut visited = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !visited.insert(id.as_u32()) {
            continue;
        }
        let Some(node) = ir.arena.node(id) else {
            return false;
        };
        match node.data {
            IrData::Upval { .. } => return true,
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::Local { .. } => {}
            IrData::SearchPath { search_path, .. } => stack.extend(search_path),
            IrData::Node(child) => stack.push(child),
            IrData::Pair { first, second } => {
                stack.push(first);
                stack.push(second);
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                stack.push(first);
                stack.push(second);
                stack.push(third);
            }
            IrData::Children(children) => {
                let Some(children) = ir.arena.child_slice(children) else {
                    return false;
                };
                stack.extend(children.iter().copied());
            }
            IrData::Bindings(bindings) => {
                if !push_binding_values_and_dynamic_keys(ir, bindings, &mut stack) {
                    return false;
                }
            }
            IrData::Binary { op, lhs, rhs } => {
                if matches!(op, BinOpKind::PipeLeft | BinOpKind::PipeRight) {
                    return false;
                }
                stack.push(lhs);
                stack.push(rhs);
            }
            IrData::Unary { operand, .. } => stack.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                stack.push(receiver);
                stack.extend(default);
                if !push_attr_path_dynamic_segments(ir, path, &mut stack) {
                    return false;
                }
            }
            IrData::HasAttr { receiver, path, .. } => {
                stack.push(receiver);
                if !push_attr_path_dynamic_segments(ir, path, &mut stack) {
                    return false;
                }
            }
            IrData::PrimOp { args, .. } => {
                let Some(args) = ir.arena.child_slice(args) else {
                    return false;
                };
                stack.extend(args.iter().copied());
            }
            IrData::DialectNode { argument, .. } => stack.push(argument),
            IrData::DialectScopeVar { chain, .. } => {
                let Some(chain) = usize::try_from(chain)
                    .ok()
                    .and_then(|index| ir.with_chains.get(index))
                else {
                    return false;
                };
                stack.extend(chain.scopes.iter().copied());
            }
            IrData::Lambda { pattern, body, .. } => {
                stack.push(pattern);
                stack.push(body);
            }
            IrData::Let { bindings, body, .. } => {
                stack.push(body);
                if !push_binding_values_and_dynamic_keys(ir, bindings, &mut stack) {
                    return false;
                }
            }
            IrData::AttrSet { bindings, .. } => {
                if !push_binding_values_and_dynamic_keys(ir, bindings, &mut stack) {
                    return false;
                }
            }
            IrData::FormalSet { formals, .. } => {
                let Some(formals) = ir.arena.child_slice(formals) else {
                    return false;
                };
                stack.extend(formals.iter().copied());
            }
            IrData::Formal { default, .. } => stack.extend(default),
        }
    }
    false
}

fn push_binding_values_and_dynamic_keys(
    ir: &Ir,
    bindings: IrBindingSlice,
    stack: &mut Vec<IrId>,
) -> bool {
    let start = bindings.start as usize;
    let Some(end) = start.checked_add(bindings.len()) else {
        return false;
    };
    let Some(bindings) = ir.bindings.get(start..end) else {
        return false;
    };
    for binding in bindings {
        stack.push(binding.value);
        if let IrAttrPathSegment::Dynamic(segment) = binding.key {
            stack.push(segment);
        }
    }
    true
}

fn push_attr_path_dynamic_segments(ir: &Ir, path: IrAttrPathId, stack: &mut Vec<IrId>) -> bool {
    let Some(segments) = ir.attr_paths.get(path.index()) else {
        return false;
    };
    for segment in segments.as_ref() {
        if let IrAttrPathSegment::Dynamic(segment) = segment {
            stack.push(*segment);
        }
    }
    true
}

fn captured_fulfilled_slot_with_cached_tag(
    evaluator: &TreeWalk,
    thunk_value: Value,
    frame_index: usize,
    slot: u32,
    tag: ValueTag,
) -> Option<(Value, Value)> {
    let thunk = evaluator.heap().get_thunk(thunk_value).ok()?;
    let env = thunk.env()?;
    let value = env.frames().get(frame_index)?.get(slot).ok()?;
    let thunk = evaluator.heap().get_thunk(value).ok()?;
    let cached = thunk.cell().cached_value().ok()??;
    if cached.tag() == tag {
        return Some((value, cached));
    }
    None
}

fn attrset_has_binding_position(attrs: &FlatAttrs) -> bool {
    attrs.iter_by_symbol().any(|entry| entry.position.is_some())
}

fn source_line_column(source: &str, needle: &str) -> (usize, usize) {
    let offset = source.find(needle).expect("needle exists in source");
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix
        .bytes()
        .rposition(|byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    (line, offset - line_start + 1)
}

fn position_free_closed_literal_lazy_list_ir() -> (Ir, Symbol) {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let ir = Ir {
        root: IrId::new(4),
        arena: IrArena::from_raw_parts(
            vec![
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(8, 9),
                    IrData::Node(IrId::new(0)),
                ),
                pure_node(
                    IrKind::List,
                    Span::new(6, 11),
                    IrData::Children(IrChildSlice::new(0, 1)),
                ),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(6, 11),
                    IrData::Node(IrId::new(2)),
                ),
                pure_node(
                    IrKind::AttrSet,
                    Span::new(0, 13),
                    IrData::AttrSet {
                        shape: IrShapeId::new(0),
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            vec![IrId::new(1)],
        ),
        facts: IrFacts::conservative(5),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(a),
            position: None,
            value: IrId::new(3),
        }]
        .into_boxed_slice(),
        shapes: vec![IrShape::new(Box::new([a]))].into_boxed_slice(),
    };
    (ir, a)
}

fn position_free_closed_literal_lazy_attrset_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let ir = manual_ir_with_attr_tables(
        IrId::new(4),
        vec![
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(1)),
            pure_node(
                IrKind::ThunkAlloc,
                Span::new(12, 13),
                IrData::Node(IrId::new(0)),
            ),
            pure_node(
                IrKind::AttrSet,
                Span::new(6, 15),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(1, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
            pure_node(
                IrKind::ThunkAlloc,
                Span::new(6, 15),
                IrData::Node(IrId::new(2)),
            ),
            pure_node(
                IrKind::AttrSet,
                Span::new(0, 17),
                IrData::AttrSet {
                    shape: IrShapeId::new(1),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![
            IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value: IrId::new(3),
            },
            IrBinding {
                key: IrAttrPathSegment::Static(b),
                position: None,
                value: IrId::new(1),
            },
        ],
        vec![IrShape::new(Box::new([b])), IrShape::new(Box::new([a]))],
    );
    (ir, a, b)
}

fn position_free_source_order_attrset_ir() -> (Ir, Symbol) {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let c = symbols.intern(b"c").expect("c interns");
    let b = symbols.intern(b"b").expect("b interns");
    let ir = manual_ir_with_attr_tables(
        IrId::new(4),
        vec![
            pure_node(IrKind::Int, Span::new(10, 11), IrData::Int(2)),
            pure_node(IrKind::Int, Span::new(17, 18), IrData::Int(1)),
            pure_node(
                IrKind::AttrSet,
                Span::new(6, 20),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(1, 2),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
            pure_node(
                IrKind::ThunkAlloc,
                Span::new(6, 20),
                IrData::Node(IrId::new(2)),
            ),
            pure_node(
                IrKind::AttrSet,
                Span::new(0, 22),
                IrData::AttrSet {
                    shape: IrShapeId::new(1),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![
            IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value: IrId::new(3),
            },
            IrBinding {
                key: IrAttrPathSegment::Static(c),
                position: None,
                value: IrId::new(0),
            },
            IrBinding {
                key: IrAttrPathSegment::Static(b),
                position: None,
                value: IrId::new(1),
            },
        ],
        vec![IrShape::new(Box::new([c, b])), IrShape::new(Box::new([a]))],
    );
    (ir, a)
}

fn manual_inline_capture_force_ir(captured: i64) -> Ir {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frame = FrameId::new(0);
    Ir {
        root: IrId::new(5),
        arena: IrArena::from_raw_parts(
            vec![
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(captured)),
                pure_node(
                    IrKind::LocalVar,
                    Span::new(18, 19),
                    IrData::Local { slot: 0 },
                ),
                pure_node(IrKind::Int, Span::new(22, 23), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(18, 23),
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(1),
                        rhs: IrId::new(2),
                    },
                ),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(18, 23),
                    IrData::Node(IrId::new(3)),
                ),
                pure_node(
                    IrKind::Let,
                    Span::new(0, 23),
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 1),
                        body: IrId::new(4),
                        frame: Some(frame),
                    },
                ),
            ],
            Vec::new(),
        ),
        facts: IrFacts::conservative(6),
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: false,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(x),
            position: None,
            value: IrId::new(0),
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}
