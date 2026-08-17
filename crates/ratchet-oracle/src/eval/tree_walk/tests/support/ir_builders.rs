//! Tree-walk test support: manual IR construction helpers.

use super::*;

pub(crate) fn symbol_for(ir: &Ir, name: &[u8]) -> Symbol {
    let index = ir
        .symbols
        .symbols()
        .iter()
        .position(|symbol| symbol.as_slice() == name)
        .expect("symbol exists");
    Symbol::new(index as u32)
}

pub(crate) fn primop_argument(ir: &Ir, index: usize) -> (IrId, Span) {
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .get(index)
        .copied()
        .expect("primop argument exists");
    let span = ir.arena.node(argument).expect("argument exists").span;
    (argument, span)
}

pub(crate) fn empty_ir(root: IrId, arena: IrArena) -> Ir {
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

pub(crate) fn pure_node(kind: IrKind, span: Span, data: IrData) -> IrNode {
    IrNode::new(kind, span, EffectClass::pure(), data)
}

pub(crate) fn manual_ir(root: IrId, nodes: Vec<IrNode>) -> Ir {
    empty_ir(root, IrArena::from_raw_parts(nodes, Vec::new()))
}

pub(crate) fn manual_ir_with_symbols(root: IrId, nodes: Vec<IrNode>, symbols: SymbolTable) -> Ir {
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

pub(crate) fn manual_ir_with_symbols_and_frames(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    frames: Vec<FrameInfo>,
) -> Ir {
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: frames.into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

pub(crate) fn manual_ir_with_with_chains(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    with_chains: Vec<IrWithChain>,
) -> Ir {
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: with_chains.into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

pub(crate) fn manual_ir_with_attr_tables(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    bindings: Vec<IrBinding>,
    shapes: Vec<IrShape>,
) -> Ir {
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: bindings.into_boxed_slice(),
        shapes: shapes.into_boxed_slice(),
    }
}

pub(crate) fn manual_ir_with_attr_paths(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    attr_paths: Vec<Box<[IrAttrPathSegment]>>,
) -> Ir {
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: attr_paths.into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

pub(crate) fn int_binary_ir(op: BinOpKind, left: i64, right: i64) -> Ir {
    let lhs = IrId::new(0);
    let rhs = IrId::new(1);
    let root = IrId::new(2);
    manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(left)),
            pure_node(IrKind::Int, Span::new(2, 3), IrData::Int(right)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 3),
                IrData::Binary { op, lhs, rhs },
            ),
        ],
    )
}
