//! Source-language frontend data structures.
//!
//! The frontend starts with a byte-oriented lexer and grows into the compact
//! arena AST, recursive-descent parser, scope resolver, and parse cache required
//! by RFC-0007 Phase 1.
//!
//! This is the `aos-nix-syntax` crate — the SAFE Nix-dialect frontend of the
//! RFC-0007 §1.1 crate topology, extracted from the former `aos-nix::syntax`
//! module (Phase 1b). It depends on no other workspace crate.
#![forbid(unsafe_code)]

pub mod ast;
pub mod lexer;
pub mod parser;

pub use ast::{
    AstArena, AstError, AstErrorKind, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind,
    ParsedAst, SharedSymbolAdmission, SharedSymbolAdmissionKind, SharedSymbolTable,
    SharedSymbolTableError, Symbol, SymbolTable, UnaryOpKind,
};
pub use lexer::{LexError, LexErrorKind, Lexer, Span, Token, TokenKind};
pub use parser::{
    ParseError, ParseErrorKind, Parser, parse_bytes, parse_bytes_with_symbols, parse_str,
    parse_str_with_symbols,
};
