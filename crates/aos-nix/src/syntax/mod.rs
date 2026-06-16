//! Source-language frontend data structures.
//!
//! The frontend starts with a byte-oriented lexer and grows into the compact
//! arena AST, recursive-descent parser, scope resolver, and parse cache required
//! by RFC-0007 Phase 1.

pub mod lexer;

pub use lexer::{LexError, LexErrorKind, Lexer, Span, Token, TokenKind};
