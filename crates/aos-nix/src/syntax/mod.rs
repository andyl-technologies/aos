//! Source-language frontend data structures.
//!
//! The frontend starts with a byte-oriented lexer and grows into the compact
//! arena AST, recursive-descent parser, scope resolver, and parse cache required
//! by RFC-0007 Phase 1.

pub mod ast;
pub mod lexer;
pub mod parser;

pub use ast::{
    AstArena, AstError, AstErrorKind, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind,
    ParsedAst, Symbol, SymbolTable, UnaryOpKind,
};
pub use lexer::{LexError, LexErrorKind, Lexer, Span, Token, TokenKind};
pub use parser::{ParseError, ParseErrorKind, Parser, parse_bytes, parse_str};
