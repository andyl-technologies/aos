//! Force-cache subject tests for captured unsupported and synthetic values.

use super::*;
mod part_1;
mod part_2;
mod part_3;

fn static_selects_for_symbol(ir: &Ir, name: &[u8]) -> Vec<(IrId, IrAttrPathId)> {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            let IrData::Select { path, .. } = node.data else {
                return None;
            };
            let segments = ir.attr_paths.get(path.index())?;
            if segments.len() != 1 {
                return None;
            }
            let IrAttrPathSegment::Static(symbol) = segments[0] else {
                return None;
            };
            (ir.symbols.resolve(symbol) == Some(name)).then_some((IrId::new(index as u32), path))
        })
        .collect()
}

fn captured_static_select_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(1),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::Select,
                Span::new(0, 6),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: None,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    (ir, used, unused)
}

fn captured_static_select_thunk_for_attrs(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Value,
    unused_value: Value,
) -> Value {
    captured_static_select_thunk_for_attrs_with_position(
        evaluator,
        ir,
        used,
        unused,
        selected_value,
        None,
        unused_value,
    )
}

fn captured_static_select_thunk_for_attrs_with_position(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Value,
    selected_position: Option<AttrPosition>,
    unused_value: Value,
) -> Value {
    let selected_entry = match selected_position {
        Some(position) => AttrEntry::with_position(used, selected_value, position),
        None => AttrEntry::new(used, selected_value),
    };
    let attrs = FlatAttrs::new(
        vec![selected_entry, AttrEntry::new(unused, unused_value)],
        &evaluator.symbols,
    )
    .expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured static select thunk allocates")
}

fn captured_static_select_default_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::LocalVar,
                Span::new(10, 17),
                IrData::Local { slot: 1 },
            ),
            pure_node(
                IrKind::Select,
                Span::new(0, 17),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: Some(IrId::new(1)),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    (ir, used, unused)
}

fn captured_static_select_default_nested_let_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let default = symbols.intern(b"default").expect("default interns");
    let path = IrAttrPathId::new(0);
    let nodes = vec![
        pure_node(
            IrKind::UpvalVar,
            Span::new(0, 1),
            IrData::Upval { depth: 1, slot: 0 },
        ),
        pure_node(
            IrKind::UpvalVar,
            Span::new(10, 17),
            IrData::Upval { depth: 1, slot: 1 },
        ),
        pure_node(
            IrKind::LocalVar,
            Span::new(27, 34),
            IrData::Local { slot: 0 },
        ),
        pure_node(
            IrKind::Select,
            Span::new(20, 34),
            IrData::Select {
                site: IrInlineCacheSiteId::new(0),
                receiver: IrId::new(0),
                path,
                default: Some(IrId::new(2)),
            },
        ),
        pure_node(
            IrKind::Let,
            Span::new(0, 34),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: IrId::new(3),
                frame: Some(FrameId::new(0)),
            },
        ),
    ];
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(4),
        arena,
        facts,
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: true,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: vec![Box::new([IrAttrPathSegment::Static(used)]) as Box<[IrAttrPathSegment]>]
            .into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(default),
            position: Some(Span::new(4, 11)),
            value: IrId::new(1),
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    (ir, used, unused)
}

fn captured_static_select_default_thunk_for_attrs(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Option<Value>,
    unused_value: Value,
    default_value: Value,
) -> Value {
    let mut entries = Vec::new();
    if let Some(selected_value) = selected_value {
        entries.push(AttrEntry::new(used, selected_value));
    }
    entries.push(AttrEntry::new(unused, unused_value));
    let attrs = FlatAttrs::new(entries, &evaluator.symbols).expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(2).expect("capture frame allocates");
    frame
        .set(0, captured)
        .expect("receiver capture frame slot sets");
    frame
        .set(1, default_value)
        .expect("default capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured defaulted static select thunk allocates")
}

fn unhashable_apply_thunk(evaluator: &mut TreeWalk, id: IrId) -> Value {
    evaluator
        .alloc_apply_thunk(
            id,
            Span::new(20, 21),
            id,
            Span::new(20, 21),
            Value::int(1),
            id,
            Value::int(2),
        )
        .expect("unhashable apply thunk allocates")
}

// Builds synthetic position-free IR rather than parser-lowered source IR so
// attr position metadata does not block the replayable payload path under test.
