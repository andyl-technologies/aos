//! Lowering tests for the arena IR.
//!
//! Shared fixtures live here; the test functions are split across
//! [`lowering_tests`] and [`primop_tests`] submodules.

use super::*;
use crate::compile::{ScopeTables, resolve};
use crate::syntax::{AstArena, parse_str};

pub(super) fn lowered(source: &str) -> Ir {
    lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("IR lowers")
}

pub(super) fn node(ir: &Ir, id: IrId) -> &IrNode {
    ir.arena.node(id).expect("IR node exists")
}

pub(super) fn root_node(ir: &Ir) -> &IrNode {
    node(ir, ir.root)
}

pub(super) fn thunk_inner(ir: &Ir, id: IrId) -> IrId {
    assert_eq!(node(ir, id).kind, IrKind::ThunkAlloc);
    let IrData::Node(inner) = node(ir, id).data else {
        panic!("thunk payload expected");
    };
    inner
}

pub(super) fn manual_resolved_ast(root: NodeId, nodes: Vec<Node>) -> ResolvedAst {
    let node_count = nodes.len();
    ResolvedAst {
        root,
        arena: AstArena::from_raw_parts(nodes, Vec::new()),
        symbols: SymbolTable::new(),
        scopes: ScopeTables::from_raw_parts(
            Vec::new(),
            vec![None; node_count],
            Vec::new(),
            Vec::new(),
            vec![None; node_count],
        ),
    }
}

pub(super) fn lookup_site(ir: &Ir, id: IrId) -> IrInlineCacheSiteId {
    match node(ir, id).data {
        IrData::Select { site, .. } | IrData::HasAttr { site, .. } => site,
        _ => panic!("lookup payload expected"),
    }
}

pub(super) fn symbol_text<'a>(ir: &'a Ir, symbol: Symbol) -> &'a [u8] {
    ir.symbols.resolve(symbol).expect("symbol exists")
}

mod lowering_tests;
mod primop_shadowing_tests;
mod primop_tests;
