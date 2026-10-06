//! Predicate-engine differential matching and original-account custody tests.

use super::*;
use crate::model::RegexProgram;
use crate::owned_decode::DecodeResourceAuthority;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct Receipt {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Receipt {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other(
                    "original regex allowance exhausted",
                ))
            })?;
        Ok(Arc::new(Receipt {
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

fn account(maximum: u64) -> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let used = Arc::new(AtomicU64::new(0));
    let authority = Arc::new(Authority {
        used: Arc::clone(&used),
        maximum,
    });
    Ok((DecodeBudget::new(authority, maximum)?, used))
}

#[test]
fn pike_matching_preserves_byte_regex_syntax_and_leftmost_ranges() -> Result<(), Box<dyn Error>> {
    let patterns = [
        "",
        "a",
        "a|ab",
        "ab|a",
        "(?:a?)*",
        "a{0,3}?",
        "(?m:^a+$)",
        "(?mR:^a$)",
        "(?s:.)",
        "(?-u:.)",
        "(?-u:\\xFF+)",
        "\\b\\w+\\b",
        "(?-u:\\b)\\w+",
        "\\p{Greek}+",
        "(?i:Σ|k|ſ)",
        "[a-z&&[^aeiou]]+",
        "[\\p{Age=3.0}--\\p{ASCII}]+",
        "(?P<name>a+)(?:b|c)",
        "a+?",
        "a{2,5}",
        "foo|foobar|fooquux|quux",
        "(?:ab|ac|ad){3}",
        "(?x: a \\x20 b )",
        "\\A[a-z]*\\z",
        "[^\\x00-\\x7F]",
        "(?i:[a-z])",
        "\\p{Grapheme_Base}",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"aaaab",
        b"foofoobarfooquuxquux",
        b"aba",
        b"\na\r\na\n",
        b"a b",
        b"\xFF\xFEa\xFF",
        b"\xC3\xA9\xFF",
        "Σσς KkK Ssſ Δάφνη".as_bytes(),
    ];

    for pattern in patterns {
        let original = regex::bytes::Regex::new(pattern)?;
        let compiled = CompiledPredicate::compile(pattern)?;
        for bytes in haystacks {
            let mut cache = compiled.engine.create_cache();
            let actual = compiled
                .engine
                .find_iter(&mut cache, *bytes)
                .map(|matched| matched.range())
                .collect::<Vec<_>>();
            let expected = original
                .find_iter(bytes)
                .map(|matched| matched.range())
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "pattern {pattern:?}, bytes {bytes:?}");
            for boundary in 0..=bytes.len() {
                assert_eq!(
                    compiled.any_match_ending_after(bytes, boundary)?,
                    original
                        .find_iter(bytes)
                        .any(|matched| matched.end() > boundary),
                    "pattern {pattern:?}, bytes {bytes:?}, boundary {boundary}",
                );
            }
        }
    }
    Ok(())
}

#[test]
fn invalid_syntax_matches_original_rejection() {
    for pattern in ["(", "[", "a{3,2}", "(?=a)", "(a)\\1", "\\p{NoSuchProperty}"] {
        assert!(regex::bytes::Regex::new(pattern).is_err());
        assert!(matches!(
            CompiledPredicate::compile(pattern),
            Err(PredicateRegexError::Syntax(_))
        ));
    }
}

#[test]
fn counted_repetition_refuses_before_thompson_allocation() -> Result<(), Box<dyn Error>> {
    let (budget, used) = account(2 * 1024 * 1024)?;
    let scope = budget.enter();
    let compiled = CompiledPredicate::compile("(?:ab|ac){1000000000}");
    assert!(matches!(compiled, Err(PredicateRegexError::Admission(_))));
    assert!(budget.check().is_err());
    assert!(used.load(Ordering::SeqCst) <= 2 * 1024 * 1024);

    drop(scope);
    drop(budget);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn compiled_origin_and_independent_search_caches_retain_exact_loan_lifetime()
-> Result<(), Box<dyn Error>> {
    let (budget, used) = account(32 * 1024 * 1024)?;
    let scope = budget.enter();
    let program = RegexProgram::from_pattern("(?i:hello)|\\p{Greek}+");
    let compiled = program.compiled()?;
    let retained = used.load(Ordering::SeqCst);
    assert!(retained > 0);
    for _ in 0..50 {
        assert!(compiled.any_match_ending_after("HELLO Δ".as_bytes(), 0)?);
        assert_eq!(used.load(Ordering::SeqCst), retained);
    }
    drop(scope);
    drop(budget);
    drop(program);
    assert_eq!(used.load(Ordering::SeqCst), retained);

    let mut workers = Vec::new();
    for _ in 0..4 {
        let independent = Arc::clone(&compiled);
        workers.push(std::thread::spawn(move || {
            independent.any_match_ending_after(b"hello", 1)
        }));
    }
    for worker in workers {
        assert!(
            worker
                .join()
                .map_err(|_| std::io::Error::other("regex worker panicked"))??
        );
    }
    assert_eq!(used.load(Ordering::SeqCst), retained);
    drop(compiled);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn uncredited_component_cache_cannot_enter_admitted_model() -> Result<(), Box<dyn Error>> {
    let program = RegexProgram::from_pattern("hello");
    let component = program.compiled()?;
    assert!(!component.has_admission());

    let (budget, _) = account(1024 * 1024)?;
    let _scope = budget.enter();
    assert!(matches!(
        program.compiled(),
        Err(PredicateRegexError::Admission(_))
    ));
    assert!(budget.check().is_err());
    Ok(())
}

#[test]
fn geometry_covers_actual_final_nfa_and_search_cache() -> Result<(), Box<dyn Error>> {
    for pattern in [
        "a",
        "a{500}",
        "\\p{Greek}",
        "\\p{Grapheme_Base}",
        "ab|abc|abcd|ac|b",
    ] {
        let parsed = syntax::parse(pattern)?;
        let bound = geometry::compiler_geometry(&parsed.hir)?;
        let compiled = CompiledPredicate::compile(pattern)?;
        let nfa = compiled.engine.get_nfa();
        assert!(nfa.memory_usage() <= bound.logical_limit);
        let mut cache = compiled.engine.create_cache();
        let _ = compiled
            .engine
            .find_iter(&mut cache, "abcd Δ".as_bytes())
            .count();
        assert!((cache.memory_usage() as u64) <= compiled.search_bytes);
    }
    Ok(())
}
