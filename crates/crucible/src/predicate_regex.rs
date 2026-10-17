//! Admitted byte-oriented predicate compilation and isolated PikeVM searches.
//!
//! Syntax, compilation and search reserve concrete storage from the original
//! decode authority. Compiled programs retain their credit; each search owns
//! an independent temporary cache, so concurrent predicates share no mutable
//! matcher state. Explicit capture syntax remains valid, while only the
//! overall match span is tracked because predicates never observe subgroups.

use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};
use regex_automata::nfa::thompson::{self, WhichCaptures, pikevm::PikeVM};
use std::error::Error;
use std::sync::Arc;

mod geometry;
mod syntax;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PredicateRegexError {
    #[error("predicate regex resource admission refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    #[error("predicate regex syntax rejected: {0}")]
    Syntax(#[source] Box<dyn Error + Send + Sync>),
    #[error("predicate regex compilation rejected: {0}")]
    Compile(#[source] Box<dyn Error + Send + Sync>),
}

pub(crate) struct CompiledPredicate {
    engine: PikeVM,
    search_bytes: u64,
    custody: Option<DecodeCustody>,
}

impl std::fmt::Debug for CompiledPredicate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledPredicate")
            .field("states", &self.engine.get_nfa().states().len())
            .field("admitted", &self.custody.is_some())
            .finish()
    }
}

impl CompiledPredicate {
    pub(crate) fn compile(pattern: &str) -> Result<Arc<Self>, PredicateRegexError> {
        let parsed = syntax::parse(pattern)?;
        let bound = geometry::compiler_geometry(&parsed.hir)?;
        let budget = crate::owned_decode::current_budget();
        let scratch = reserve_scratch(budget.as_ref(), bound.temporary_bytes)?;
        // The HIR-only compiler cannot construct a pattern-owning Syntax
        // error, and implicit captures cannot construct duplicate-name data.
        // Its remaining errors are inline fields. Admit their boxed wrapper
        // separately so a returned error outlives the compiler scratch loan.
        let error_credit = reserve_scratch(
            budget.as_ref(),
            std::mem::size_of::<CompileFailure>() as u64,
        )?;
        let result = thompson::Compiler::new()
            .configure(
                thompson::Config::new()
                    .utf8(false)
                    .reverse(false)
                    .shrink(false)
                    .which_captures(WhichCaptures::Implicit)
                    .nfa_size_limit(Some(bound.logical_limit)),
            )
            .build_from_hir(&parsed.hir);
        let nfa = match result {
            Ok(nfa) => nfa,
            Err(source) => return Err(compile_failure(source, error_credit)),
        };
        let retained_bytes = geometry::retained_bytes(&nfa)?;
        charge_retained(budget.as_ref(), retained_bytes)?;
        let search_bytes = geometry::search_bytes(&nfa)?;
        let engine = match PikeVM::builder().build_from_nfa(nfa) {
            Ok(engine) => engine,
            Err(source) => return Err(compile_failure(source, error_credit)),
        };
        drop(parsed);
        drop(scratch);
        drop(error_credit);
        Ok(Arc::new(Self {
            engine,
            search_bytes,
            custody: budget.map(|budget| budget.custody()),
        }))
    }

    pub(crate) fn has_admission(&self) -> bool {
        self.custody.is_some()
    }

    pub(crate) fn any_match_ending_after(
        &self,
        bytes: &[u8],
        boundary: usize,
    ) -> Result<bool, PredicateRegexError> {
        let _scope = self.custody.as_ref().and_then(DecodeCustody::enter);
        let budget = crate::owned_decode::current_budget();
        let scratch = reserve_scratch(budget.as_ref(), self.search_bytes)?;
        let mut cache = self.engine.create_cache();
        let matched = self
            .engine
            .find_iter(&mut cache, bytes)
            .any(|matched| matched.end() > boundary);
        drop(cache);
        drop(scratch);
        Ok(matched)
    }
}

fn compile_failure(
    source: thompson::BuildError,
    credit: Option<DecodeScratch>,
) -> PredicateRegexError {
    PredicateRegexError::Compile(Box::new(CompileFailure {
        source,
        _credit: credit,
    }))
}

struct CompileFailure {
    source: thompson::BuildError,
    _credit: Option<DecodeScratch>,
}

impl std::fmt::Debug for CompileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("CompileFailure")
            .field(&self.source)
            .finish()
    }
}

impl std::fmt::Display for CompileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for CompileFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

fn reserve_scratch(
    budget: Option<&DecodeBudget>,
    bytes: u64,
) -> Result<Option<DecodeScratch>, PredicateRegexError> {
    budget
        .map(|budget| budget.reserve_scratch_bytes(bytes))
        .transpose()
        .map_err(Into::into)
}

fn charge_retained(budget: Option<&DecodeBudget>, bytes: u64) -> Result<(), PredicateRegexError> {
    if let Some(budget) = budget {
        budget.charge_bytes(bytes)?;
    }
    Ok(())
}
