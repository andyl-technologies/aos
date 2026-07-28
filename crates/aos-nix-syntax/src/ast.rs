//! Compact arena AST for parsed Nix source.
//!
//! The parser stores every expression and syntactic helper node in a flat
//! [`AstArena`]. Cross-references are [`NodeId`] values, which are stable `u32`
//! indices rather than pointers. Variable-arity children live contiguously in
//! the arena's child pool and are referenced through [`ChildSlice`].

use std::cell::RefCell;
use std::convert::TryFrom;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use super::Span;

/// An index into the AST arena.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// Creates a node id from a raw arena index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` arena index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the arena index as a `usize`.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An interned identifier, attribute key, or literal-text handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(u32);

impl Symbol {
    /// Creates a symbol from a raw interner index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` interner index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A dense append-only symbol table with a cached lexicographic rank view.
///
/// Parsers can start from an empty table for isolated file-local ids or thread
/// an existing table across files for process-wide ids. Cache serialization
/// remaps process-wide ids back to deterministic file-local tables.
#[derive(Clone, Debug, Default)]
pub struct SymbolTable {
    by_text: BTreeMap<Vec<u8>, Symbol>,
    text: Vec<Vec<u8>>,
    lexicographic_prefixes: Vec<u64>,
    lexicographic_ranks: RefCell<LexicographicRanks>,
}

/// Lazily rebuilt dense rank view over a [`SymbolTable`].
///
/// Interning marks the view dirty instead of re-sorting; the first rank query
/// after an intern rebuilds it in O(len) by walking `by_text` in key order
/// (the map is already byte-sorted, so no comparison sort is needed).
#[derive(Clone, Debug, Default)]
struct LexicographicRanks {
    rank_by_symbol: Vec<u32>,
    dirty: bool,
}

impl SymbolTable {
    /// Creates an empty symbol table.
    pub const fn new() -> Self {
        Self {
            by_text: BTreeMap::new(),
            text: Vec::new(),
            lexicographic_prefixes: Vec::new(),
            lexicographic_ranks: RefCell::new(LexicographicRanks {
                rank_by_symbol: Vec::new(),
                dirty: false,
            }),
        }
    }

    /// Returns the number of interned byte strings.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns whether the table has no symbols.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Estimates the table's resident heap bytes for memory attribution.
    ///
    /// Sums the interned byte strings (stored twice — once in `text`, once as
    /// `by_text` keys), the `Vec`/`BTreeMap` structural overhead, and the lazy
    /// rank view. The per-`BTreeMap`-entry constant is an estimate (node packing
    /// is not observable), so the result is an attribution aid, not an exact
    /// allocator figure. Used by the memory-campaign eval-stats attribution
    /// (RFC-0007 doc 15 §5.4 scoreboard).
    pub fn resident_bytes(&self) -> usize {
        const BTREE_ENTRY_OVERHEAD: usize = 32;
        let vec_of_bytes = std::mem::size_of::<Vec<u8>>();
        let text_bytes = self.text.iter().map(Vec::capacity).sum::<usize>()
            + self.text.capacity() * vec_of_bytes;
        let key_bytes = self.by_text.keys().map(Vec::capacity).sum::<usize>()
            + self.by_text.len()
                * (vec_of_bytes + std::mem::size_of::<Symbol>() + BTREE_ENTRY_OVERHEAD);
        let rank_bytes = self.lexicographic_ranks.borrow().rank_by_symbol.capacity()
            * std::mem::size_of::<u32>();
        let prefix_bytes = self.lexicographic_prefixes.capacity() * std::mem::size_of::<u64>();
        text_bytes + key_bytes + rank_bytes + prefix_bytes
    }

    /// Interns a byte string and returns its dense symbol id.
    ///
    /// # Errors
    ///
    /// Returns [`AstErrorKind::TooManySymbols`] if the next symbol id would not
    /// fit in `u32`.
    pub fn intern(&mut self, bytes: &[u8]) -> Result<Symbol, AstError> {
        if let Some(symbol) = self.by_text.get(bytes) {
            return Ok(*symbol);
        }

        let raw = u32::try_from(self.text.len()).map_err(|_| {
            AstError::new(AstErrorKind::TooManySymbols, Span::new(u32::MAX, u32::MAX))
        })?;
        let symbol = Symbol::new(raw);
        let owned = bytes.to_vec();
        self.text.push(owned.clone());
        self.lexicographic_prefixes
            .push(symbol_lexicographic_prefix(bytes));
        self.by_text.insert(owned, symbol);
        self.lexicographic_ranks.get_mut().dirty = true;
        Ok(symbol)
    }

    /// Returns the symbol id already interned for `bytes`.
    pub fn lookup(&self, bytes: &[u8]) -> Option<Symbol> {
        self.by_text.get(bytes).copied()
    }

    /// Returns the bytes for an interned symbol.
    pub fn resolve(&self, symbol: Symbol) -> Option<&[u8]> {
        self.text.get(symbol.as_u32() as usize).map(Vec::as_slice)
    }

    /// Returns an order-preserving prefix token for an interned symbol.
    ///
    /// Different tokens establish the complete raw-byte ordering. Equal tokens
    /// require comparing the resolved bytes because names can share their first
    /// seven bytes.
    pub fn lexicographic_prefix(&self, symbol: Symbol) -> Option<u64> {
        self.lexicographic_prefixes
            .get(symbol.as_u32() as usize)
            .copied()
    }

    /// Returns this symbol's raw-byte lexicographic rank in the current table.
    ///
    /// Ranks are process-local and may be renumbered when later interning adds
    /// a byte string that sorts before existing symbols. They are not durable
    /// cache keys; use them only to compare symbols that are known to belong to
    /// this table snapshot.
    pub fn lexicographic_rank(&self, symbol: Symbol) -> Option<u32> {
        let mut ranks = self.lexicographic_ranks.borrow_mut();
        if ranks.dirty {
            ranks.rank_by_symbol.clear();
            ranks.rank_by_symbol.resize(self.text.len(), 0);
            for (rank, interned) in self.by_text.values().enumerate() {
                ranks.rank_by_symbol[interned.as_u32() as usize] = rank as u32;
            }
            ranks.dirty = false;
        }
        ranks.rank_by_symbol.get(symbol.as_u32() as usize).copied()
    }

    /// Returns all symbol byte strings in dense-id order.
    pub fn symbols(&self) -> &[Vec<u8>] {
        &self.text
    }
}

/// Packs the first seven bytes into an order-preserving 63-bit token.
fn symbol_lexicographic_prefix(bytes: &[u8]) -> u64 {
    let mut prefix = 0_u64;
    for index in 0..7 {
        prefix <<= 9;
        prefix |= bytes
            .get(index)
            .map_or(0, |byte| u64::from(*byte) + 1);
    }
    prefix
}

/// A same-process shared symbol table with idempotent insert-or-get admission.
///
/// This is a correctness precursor for the future concurrent evaluator symbol
/// interner. It preserves the existing dense [`SymbolTable`] representation and
/// serializes access with a standard-library mutex; it is not the final
/// lock-free append-only table.
#[derive(Clone, Debug, Default)]
pub struct SharedSymbolTable {
    inner: Arc<Mutex<SymbolTable>>,
}

impl SharedSymbolTable {
    /// Creates an empty shared symbol table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SymbolTable::new())),
        }
    }

    /// Creates a shared symbol table from an existing dense table.
    pub fn from_table(table: SymbolTable) -> Self {
        Self {
            inner: Arc::new(Mutex::new(table)),
        }
    }

    /// Interns a byte string and reports whether this call inserted it.
    ///
    /// # Errors
    ///
    /// Returns [`SharedSymbolTableError::Poisoned`] if another caller panicked
    /// while holding the shared table lock. Returns
    /// [`SharedSymbolTableError::Ast`] if the underlying dense table cannot
    /// allocate another symbol id.
    pub fn intern(&self, bytes: &[u8]) -> Result<SharedSymbolAdmission, SharedSymbolTableError> {
        let mut table = self
            .inner
            .lock()
            .map_err(|_| SharedSymbolTableError::Poisoned)?;
        if let Some(symbol) = table.lookup(bytes) {
            return Ok(SharedSymbolAdmission {
                symbol,
                kind: SharedSymbolAdmissionKind::Existing,
            });
        }
        let symbol = table.intern(bytes)?;
        Ok(SharedSymbolAdmission {
            symbol,
            kind: SharedSymbolAdmissionKind::Inserted,
        })
    }

    /// Returns a cloned snapshot of the current dense symbol table.
    ///
    /// # Errors
    ///
    /// Returns [`SharedSymbolTableError::Poisoned`] if another caller panicked
    /// while holding the shared table lock.
    pub fn snapshot(&self) -> Result<SymbolTable, SharedSymbolTableError> {
        self.inner
            .lock()
            .map(|table| table.clone())
            .map_err(|_| SharedSymbolTableError::Poisoned)
    }
}

/// The result of interning through a shared symbol table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedSymbolAdmission {
    symbol: Symbol,
    kind: SharedSymbolAdmissionKind,
}

impl SharedSymbolAdmission {
    /// Returns the interned symbol id.
    pub const fn symbol(self) -> Symbol {
        self.symbol
    }

    /// Returns whether the call inserted or reused the symbol.
    pub const fn kind(self) -> SharedSymbolAdmissionKind {
        self.kind
    }
}

/// Whether a shared interner call inserted or reused a symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedSymbolAdmissionKind {
    /// The call inserted a new symbol.
    Inserted,
    /// The call reused a previously interned symbol.
    Existing,
}

/// A failure while interning through a shared symbol table.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SharedSymbolTableError {
    /// The underlying dense symbol table failed.
    #[error(transparent)]
    Ast(#[from] AstError),
    /// The shared symbol-table lock was poisoned by a panicking caller.
    #[error("shared symbol table lock is poisoned")]
    Poisoned,
}

/// A contiguous run of child nodes in the arena child pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ChildSlice {
    /// The first child-pool index in the slice.
    pub start: u32,
    /// The number of child ids in the slice.
    pub len: u32,
}

impl ChildSlice {
    /// Creates a child slice from a start index and length.
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// Returns whether the slice contains no child ids.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the length as a `usize`.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns the exclusive end index when it fits in `u32`.
    pub const fn checked_end(self) -> Option<u32> {
        self.start.checked_add(self.len)
    }
}

/// One fixed-stride AST node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    /// The node's syntactic category.
    pub kind: NodeKind,
    /// The byte span covered by this node in the source file.
    pub span: Span,
    /// The kind-discriminated payload for this node.
    pub data: NodeData,
}

impl Node {
    /// Creates an AST node.
    pub const fn new(kind: NodeKind, span: Span, data: NodeData) -> Self {
        Self { kind, span, data }
    }
}

/// The closed AST node taxonomy used before scope resolution.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// An integer literal.
    Int,
    /// A floating-point literal.
    Float,
    /// A double-quoted or indented string literal fragment.
    Str,
    /// A path literal.
    Path,
    /// A search-path literal such as `<nixpkgs>`.
    SearchPath,
    /// A URI literal.
    Uri,
    /// An unresolved identifier.
    Ident,
    /// A list literal.
    List,
    /// A non-recursive attribute set.
    AttrSet,
    /// A recursive attribute set.
    RecAttrSet,
    /// A lambda expression.
    Lambda,
    /// A formal-argument set pattern.
    FormalSet,
    /// One formal argument entry.
    Formal,
    /// A function application.
    Apply,
    /// Attribute selection.
    Select,
    /// Attribute-existence test.
    HasAttr,
    /// A `let ... in ...` expression.
    LetIn,
    /// A binding inside a `let` or attribute set.
    Binding,
    /// A `with ...; ...` expression.
    With,
    /// An `assert ...; ...` expression.
    Assert,
    /// An `if ... then ... else ...` expression.
    IfThenElse,
    /// A binary operator expression.
    BinOp,
    /// A unary operator expression.
    UnaryOp,
    /// An `inherit` source marker used by desugared inherit bindings.
    Inherit,
    /// A string interpolation expression.
    Interp,
    /// A parsed attribute path.
    AttrPath,
    /// A post-resolution local variable access.
    LocalVar,
    /// A post-resolution upvalue access.
    UpvalVar,
    /// A post-resolution global variable access.
    GlobalVar,
    /// A post-resolution dynamic `with` variable access.
    WithVar,
}

/// A compact payload for an AST node.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum NodeData {
    /// The node carries no payload.
    #[default]
    None,
    /// The node carries an integer literal.
    Int(i64),
    /// The node carries a floating-point literal.
    Float(f64),
    /// The node carries an interned symbol.
    Symbol(Symbol),
    /// The node represents a search-path literal with an optional explicit
    /// `__nixPath` expression resolved from the surrounding scope.
    SearchPath {
        /// The literal text, including the surrounding angle brackets.
        literal: Symbol,
        /// The expression that should supply the lookup path, when one was
        /// resolved lexically or dynamically.
        search_path: Option<NodeId>,
    },
    /// The node references one child.
    Node(NodeId),
    /// The node references two children.
    Pair {
        /// The first child node.
        first: NodeId,
        /// The second child node.
        second: NodeId,
    },
    /// The node references three children.
    Triple {
        /// The first child node.
        first: NodeId,
        /// The second child node.
        second: NodeId,
        /// The third child node.
        third: NodeId,
    },
    /// The node references a variable-length run in the child pool.
    Children(ChildSlice),
    /// The node represents a binary operator.
    Binary {
        /// The operator being applied.
        op: BinOpKind,
        /// The left-hand operand.
        lhs: NodeId,
        /// The right-hand operand.
        rhs: NodeId,
    },
    /// The node represents a unary operator.
    Unary {
        /// The operator being applied.
        op: UnaryOpKind,
        /// The operand.
        operand: NodeId,
    },
    /// The node represents an attribute selection.
    Select {
        /// The expression being selected from.
        receiver: NodeId,
        /// The attribute-path components.
        path: ChildSlice,
        /// The optional `or` default expression.
        default: Option<NodeId>,
    },
    /// The node represents a has-attribute test.
    HasAttr {
        /// The expression being tested.
        receiver: NodeId,
        /// The attribute-path components.
        path: ChildSlice,
    },
    /// The node represents a binding.
    Binding {
        /// The binding's attribute path.
        path: ChildSlice,
        /// The right-hand expression.
        value: NodeId,
    },
    /// The node represents a `let ... in ...` expression.
    LetIn {
        /// The parsed binding nodes.
        bindings: ChildSlice,
        /// The body expression.
        body: NodeId,
    },
    /// The node represents an `inherit` source marker.
    Inherit {
        /// The optional source expression from `inherit (expr) name`.
        from: Option<NodeId>,
        /// The inherited target names as `Ident`/attribute path nodes.
        names: ChildSlice,
    },
    /// The node represents a formal-argument set.
    FormalSet {
        /// Formal entry nodes.
        formals: ChildSlice,
        /// Whether the formal set accepts extra arguments via `...`.
        ellipsis: bool,
        /// The optional `@` alias.
        alias: Option<Symbol>,
    },
    /// The node represents one formal argument.
    Formal {
        /// The formal argument name.
        name: Symbol,
        /// The optional default expression.
        default: Option<NodeId>,
    },
    /// The node represents a de Bruijn local slot.
    Local {
        /// The local frame slot.
        slot: u32,
    },
    /// The node represents a de Bruijn upvalue.
    Upval {
        /// The number of parent frames to walk.
        depth: u32,
        /// The slot inside the target frame.
        slot: u32,
    },
    /// The node represents a dynamic variable access through active `with`
    /// scopes.
    WithVar {
        /// The unresolved symbol to probe in each active `with` attrset.
        symbol: Symbol,
        /// The resolver side-table id of the innermost-first `with` chain.
        chain: u32,
    },
}

/// A binary operator in the AST.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    /// Numeric addition or string/path concatenation.
    Add,
    /// Numeric subtraction.
    Sub,
    /// Numeric multiplication.
    Mul,
    /// Numeric division.
    Div,
    /// List concatenation (`++`).
    Concat,
    /// Attribute-set update (`//`).
    Update,
    /// Less-than comparison.
    Lt,
    /// Greater-than comparison.
    Gt,
    /// Less-than-or-equal comparison.
    Le,
    /// Greater-than-or-equal comparison.
    Ge,
    /// Equality comparison.
    Eq,
    /// Inequality comparison.
    Ne,
    /// Short-circuiting logical AND.
    And,
    /// Short-circuiting logical OR.
    Or,
    /// Short-circuiting logical implication.
    Impl,
    /// Experimental forward pipe.
    PipeRight,
    /// Experimental reverse pipe.
    PipeLeft,
}

/// A unary operator in the AST.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnaryOpKind {
    /// Numeric negation.
    Neg,
    /// Boolean negation.
    Not,
}

/// A parsed Nix source file or expression.
#[derive(Clone, Debug)]
pub struct ParsedAst {
    /// The expression root node.
    pub root: NodeId,
    /// The arena containing the root and every referenced node.
    pub arena: AstArena,
    /// Symbols referenced by the arena.
    ///
    /// This table may also contain earlier symbols when parsing with a shared
    /// append-only table.
    pub symbols: SymbolTable,
}

impl ParsedAst {
    /// Creates a parsed AST bundle.
    pub const fn new(root: NodeId, arena: AstArena, symbols: SymbolTable) -> Self {
        Self {
            root,
            arena,
            symbols,
        }
    }
}

/// A compact arena of AST nodes plus a variable-arity child pool.
#[derive(Clone, Debug, Default)]
pub struct AstArena {
    nodes: Vec<Node>,
    children: Vec<NodeId>,
}

impl AstArena {
    /// Creates an empty AST arena.
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Creates an empty AST arena with space for nodes and child ids.
    pub fn with_capacity(nodes: usize, children: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(nodes),
            children: Vec::with_capacity(children),
        }
    }

    /// Creates an arena from already-decoded raw storage.
    ///
    /// Exposed for the parse-cache hydration path in downstream crates
    /// (`aos-nix`'s `cache::parse`), which reconstructs an arena from its
    /// serialized node/child vectors.
    pub fn from_raw_parts(nodes: Vec<Node>, children: Vec<NodeId>) -> Self {
        Self { nodes, children }
    }

    /// Returns the number of nodes allocated in the arena.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the arena has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns all nodes in allocation order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns the raw child pool.
    pub fn child_pool(&self) -> &[NodeId] {
        &self.children
    }

    /// Allocates one node and returns its id.
    ///
    /// # Errors
    ///
    /// Returns [`AstErrorKind::TooManyNodes`] if the next node index would not
    /// fit in a [`NodeId`].
    pub fn push_node(
        &mut self,
        kind: NodeKind,
        span: Span,
        data: NodeData,
    ) -> Result<NodeId, AstError> {
        let raw = u32::try_from(self.nodes.len()).map_err(|_| {
            AstError::new(AstErrorKind::TooManyNodes, Span::new(u32::MAX, u32::MAX))
        })?;
        let id = NodeId::new(raw);
        self.nodes.push(Node::new(kind, span, data));
        Ok(id)
    }

    /// Appends a run of child ids to the child pool.
    ///
    /// # Errors
    ///
    /// Returns [`AstErrorKind::TooManyChildren`] if either the start offset or
    /// length cannot be represented as `u32`.
    pub fn push_child_slice(&mut self, children: &[NodeId]) -> Result<ChildSlice, AstError> {
        let start = u32::try_from(self.children.len()).map_err(|_| {
            AstError::new(AstErrorKind::TooManyChildren, Span::new(u32::MAX, u32::MAX))
        })?;
        let len = u32::try_from(children.len()).map_err(|_| {
            AstError::new(AstErrorKind::TooManyChildren, Span::new(u32::MAX, u32::MAX))
        })?;
        start.checked_add(len).ok_or_else(|| {
            AstError::new(AstErrorKind::TooManyChildren, Span::new(u32::MAX, u32::MAX))
        })?;

        self.children.extend_from_slice(children);
        Ok(ChildSlice::new(start, len))
    }

    /// Returns a node by id.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.index())
    }

    /// Returns a mutable node by id.
    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(id.index())
    }

    /// Returns the child ids covered by a child slice.
    ///
    /// # Errors
    ///
    /// Returns [`AstErrorKind::InvalidChildSlice`] if the slice does not point
    /// into the arena's child pool.
    pub fn child_slice(&self, slice: ChildSlice) -> Result<&[NodeId], AstError> {
        let start = slice.start as usize;
        let end = slice.checked_end().ok_or_else(|| {
            AstError::new(
                AstErrorKind::InvalidChildSlice {
                    start,
                    len: slice.len(),
                },
                Span::new(u32::MAX, u32::MAX),
            )
        })? as usize;
        self.children.get(start..end).ok_or_else(|| {
            AstError::new(
                AstErrorKind::InvalidChildSlice {
                    start,
                    len: slice.len(),
                },
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }
}

/// An AST arena failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct AstError {
    kind: AstErrorKind,
    span: Span,
}

impl AstError {
    /// Creates an AST error.
    pub const fn new(kind: AstErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub const fn kind(&self) -> &AstErrorKind {
        &self.kind
    }

    /// Returns the source span associated with the error.
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// The category of an AST arena failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AstErrorKind {
    /// The symbol table contains more symbols than a `u32` id can address.
    #[error("too many AST symbols")]
    TooManySymbols,
    /// The arena contains more nodes than a `u32` id can address.
    #[error("too many AST nodes")]
    TooManyNodes,
    /// The child pool contains more entries than a `u32` slice can address.
    #[error("too many AST child ids")]
    TooManyChildren,
    /// A child slice does not point into the arena's child pool.
    #[error("invalid child slice start {start} length {len}")]
    InvalidChildSlice {
        /// The invalid child-pool start offset.
        start: usize,
        /// The invalid child-pool length.
        len: usize,
    },
}

#[cfg(test)]
mod tests;
