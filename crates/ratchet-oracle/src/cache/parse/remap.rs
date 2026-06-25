//! File-local symbol remapping applied before parse artifacts are serialized.
//!
//! Symbol ids in a freshly resolved AST reflect process-global interner
//! allocation order, which is not stable across processes. Remapping to a
//! deterministic file-local [`SymbolTable`] makes the serialized artifacts
//! content-addressable independent of interner history.

use super::*;

pub(super) fn file_local_resolved(resolved: &ResolvedAst) -> Result<ResolvedAst, ParseCacheError> {
    let mut remapper = SymbolRemapper::new();
    let mut nodes = Vec::with_capacity(resolved.arena.nodes().len());
    for node in resolved.arena.nodes() {
        nodes.push(Node::new(
            node.kind,
            node.span,
            remapper.remap_node_data(&resolved.symbols, node.data)?,
        ));
    }

    let mut inherit_resolutions = Vec::with_capacity(resolved.scopes.inherit_resolutions().len());
    for inherit in resolved.scopes.inherit_resolutions() {
        let mut sources = Vec::with_capacity(inherit.sources.len());
        for source in inherit.sources.as_ref() {
            sources.push(InheritSource {
                target: remapper.local_symbol(&resolved.symbols, source.target)?,
                source: source.source,
            });
        }
        inherit_resolutions.push(InheritResolution {
            from: inherit.from,
            sources: sources.into_boxed_slice(),
        });
    }

    Ok(ResolvedAst {
        root: resolved.root,
        arena: AstArena::from_raw_parts(nodes, resolved.arena.child_pool().to_vec()),
        symbols: remapper.symbols,
        scopes: ScopeTables::from_raw_parts(
            resolved.scopes.frames().to_vec(),
            resolved.scopes.node_frames().to_vec(),
            resolved.scopes.with_chains().to_vec(),
            inherit_resolutions,
            resolved.scopes.node_inherits().to_vec(),
        ),
    })
}

struct SymbolRemapper {
    symbols: SymbolTable,
    by_old: BTreeMap<Symbol, Symbol>,
}

impl SymbolRemapper {
    fn new() -> Self {
        Self {
            symbols: SymbolTable::new(),
            by_old: BTreeMap::new(),
        }
    }

    fn local_symbol(
        &mut self,
        source_symbols: &SymbolTable,
        symbol: Symbol,
    ) -> Result<Symbol, ParseCacheError> {
        if let Some(local) = self.by_old.get(&symbol) {
            return Ok(*local);
        }

        let bytes = source_symbols.resolve(symbol).ok_or_else(|| {
            ParseCacheError::EncodeArtifact(
                "symbol id out of range before serialization".to_owned(),
            )
        })?;
        let local = self.symbols.intern(bytes).map_err(|error| {
            ParseCacheError::EncodeArtifact(format!(
                "failed to build file-local symbol table: {error}"
            ))
        })?;
        self.by_old.insert(symbol, local);
        Ok(local)
    }

    fn remap_node_data(
        &mut self,
        source_symbols: &SymbolTable,
        data: NodeData,
    ) -> Result<NodeData, ParseCacheError> {
        match data {
            NodeData::Symbol(symbol) => {
                Ok(NodeData::Symbol(self.local_symbol(source_symbols, symbol)?))
            }
            NodeData::SearchPath {
                literal,
                search_path,
            } => Ok(NodeData::SearchPath {
                literal: self.local_symbol(source_symbols, literal)?,
                search_path,
            }),
            NodeData::FormalSet {
                formals,
                ellipsis,
                alias,
            } => Ok(NodeData::FormalSet {
                formals,
                ellipsis,
                alias: alias
                    .map(|symbol| self.local_symbol(source_symbols, symbol))
                    .transpose()?,
            }),
            NodeData::Formal { name, default } => Ok(NodeData::Formal {
                name: self.local_symbol(source_symbols, name)?,
                default,
            }),
            NodeData::WithVar { symbol, chain } => Ok(NodeData::WithVar {
                symbol: self.local_symbol(source_symbols, symbol)?,
                chain,
            }),
            other => Ok(other),
        }
    }
}
