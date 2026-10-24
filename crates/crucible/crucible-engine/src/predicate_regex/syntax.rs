//! Pre-admitted AST parsing and byte-compatible HIR translation.
//!
//! The pinned syntax implementation allocates before reporting size or nesting
//! errors. A borrowed source census therefore admits its concrete peak first.
//! Parser and translation scratch close after translation; returned HIR and
//! rejected syntax sources retain their own original resource custody.

use super::{PredicateRegexError, reserve_scratch};
use crate::owned_decode::DecodeScratch;
use regex_syntax::{ast, hir};
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

mod peak;

#[cfg(test)]
mod tests;

pub(super) fn unanchored_prefix_peak() -> Result<u64, PredicateRegexError> {
    peak::unanchored_prefix_peak()
}

pub(super) struct ParsedRegex {
    pub(super) hir: hir::Hir,
    // HIR destruction itself uses a heap worklist. Its guard follows the HIR.
    _retained: Option<DecodeScratch>,
}

pub(super) fn parse(pattern: &str) -> Result<ParsedRegex, PredicateRegexError> {
    let geometry = peak::geometry(pattern)?;
    let budget = crate::owned_decode::current_budget();
    let retained = reserve_scratch(budget.as_ref(), geometry.hir_bytes)?;
    let temporary = reserve_scratch(budget.as_ref(), geometry.temporary_bytes)?;

    let mut parser = ast::parse::ParserBuilder::new()
        .nest_limit(250)
        .octal(false)
        .build();
    let ast = match parser.parse(pattern) {
        Ok(ast) => ast,
        Err(source) => {
            drop(parser);
            return Err(syntax_failure(source, temporary, retained));
        }
    };
    let mut translator = hir::translate::TranslatorBuilder::new().utf8(false).build();
    let hir = match translator.translate(pattern, &ast) {
        Ok(hir) => hir,
        Err(source) => {
            drop(translator);
            drop(ast);
            drop(parser);
            return Err(syntax_failure(source, temporary, retained));
        }
    };
    drop(translator);
    drop(ast);
    drop(parser);
    drop(temporary);
    Ok(ParsedRegex {
        hir,
        _retained: retained,
    })
}

fn syntax_failure<E: Error + Send + Sync + 'static>(
    source: E,
    temporary: Option<DecodeScratch>,
    retained: Option<DecodeScratch>,
) -> PredicateRegexError {
    PredicateRegexError::Syntax(Box::new(SyntaxFailure {
        source,
        formatter_exclusion: Mutex::new(()),
        _temporary: temporary,
        _retained: retained,
    }))
}

// Upstream errors own the input pattern. Preserve both the typed cause and its
// admitted allocation until the error owner closes, including rejected input.
struct SyntaxFailure<E> {
    source: E,
    // The error is Send + Sync. Its single admitted upstream Display
    // workspace must not back overlapping diagnostic renders.
    formatter_exclusion: Mutex<()>,
    _temporary: Option<DecodeScratch>,
    _retained: Option<DecodeScratch>,
}

impl<E: fmt::Debug> fmt::Debug for SyntaxFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SyntaxFailure")
            .field(&self.source)
            .finish()
    }
}

impl<E: fmt::Display> fmt::Display for SyntaxFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _render = self.formatter_exclusion.lock().map_err(|_| fmt::Error)?;
        self.source.fmt(formatter)
    }
}

impl<E: Error + 'static> Error for SyntaxFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
