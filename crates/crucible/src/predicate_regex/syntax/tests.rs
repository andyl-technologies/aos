//! Hostile syntax, original admission, and returned HIR/error custody witnesses.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{convert::Infallible, mem::size_of};

struct Authority {
    used: Arc<AtomicU64>,
    peak: AtomicU64,
    maximum: u64,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        let previous = self
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("test authority exhausted"))
            })?;
        self.peak.fetch_max(previous + bytes, Ordering::SeqCst);
        Ok(Arc::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

fn account(maximum: u64) -> Result<(Arc<Authority>, DecodeBudget), DecodeAdmissionError> {
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        peak: AtomicU64::new(0),
        maximum,
    });
    let budget = DecodeBudget::new(authority.clone(), maximum)?;
    Ok((authority, budget))
}

#[test]
fn original_refusal_precedes_even_invalid_parser_input() -> Result<(), Box<dyn Error>> {
    let (authority, budget) = account(1024)?;
    let scope = budget.enter();
    let initial = authority.used.load(Ordering::SeqCst);
    assert!(matches!(parse("("), Err(PredicateRegexError::Admission(_))));
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);
    drop(scope);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn temporary_syntax_credit_closes_before_retained_hir_credit() -> Result<(), Box<dyn Error>> {
    let pattern = r"(?i)(?P<name>\p{L}+)|[\p{Age=16.0}&&[^a-z]]";
    let bound = peak::geometry(pattern)?;
    let (authority, budget) = account(128 * 1024 * 1024)?;
    let scope = budget.enter();
    let initial = authority.used.load(Ordering::SeqCst);
    let parsed = parse(pattern)?;
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        initial + bound.hir_bytes
    );
    assert!(
        authority.peak.load(Ordering::SeqCst) >= initial + bound.hir_bytes + bound.temporary_bytes
    );
    let ordinary = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)?;
    assert_eq!(parsed.hir, ordinary);
    drop(ordinary);
    drop(scope);
    drop(budget);
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        initial + bound.hir_bytes
    );
    drop(parsed);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn syntax_rejection_retains_original_error_pattern_and_credit() -> Result<(), Box<dyn Error>> {
    let pattern = "(?P<invalid>";
    let (authority, budget) = account(16 * 1024 * 1024)?;
    let scope = budget.enter();
    let error = match parse(pattern) {
        Err(error) => error,
        Ok(_) => return Err("invalid fixture unexpectedly parsed".into()),
    };
    let mut cause = error.source();
    let mut found = false;
    while let Some(source) = cause {
        if let Some(syntax) = source.downcast_ref::<ast::Error>() {
            assert_eq!(syntax.pattern(), pattern);
            found = true;
        }
        cause = source.source();
    }
    assert!(found);
    drop(scope);
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(error);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn hostile_classes_and_simplification_remain_within_preparse_geometry() -> Result<(), Box<dyn Error>>
{
    for pattern in [
        r"(?i)[\p{Grapheme_Base}~~\p{Age=16.0}]",
        r"(?i)[[a-z]--[[^A-Z]&&\p{Greek}]]",
        r"(?-u:[\x80-\xFF])|(?i:Kſİ)",
        r"(?:ab\w|ab\d|ab\s)(?:é水|é木)",
        r"(?x:a # comment\n b)|[[:space:][:punct:]]",
        r"(?:|a||b|)(?P<unicode>水{0,999})",
        r"[a-z&&[^q]~~[A-Z--X]]",
    ] {
        let geometry = peak::geometry(pattern)?;
        let (authority, budget) = account(128 * 1024 * 1024)?;
        let scope = budget.enter();
        let parsed = parse(pattern);
        let ordinary = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .build()
            .parse(pattern);
        match (&parsed, &ordinary) {
            (Ok(parsed), Ok(ordinary)) => assert_eq!(&parsed.hir, ordinary, "{pattern}"),
            (Err(PredicateRegexError::Syntax(_)), Err(_)) => {}
            _ => return Err(format!("syntax outcome changed for {pattern}").into()),
        }
        assert!(authority.used.load(Ordering::SeqCst) <= authority.maximum);
        assert!(geometry.hir_bytes > 0 && geometry.temporary_bytes > 0);
        drop(parsed);
        drop(ordinary);
        drop(scope);
        drop(budget);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn nesting_rejection_is_guarded_before_upstream_construction() -> Result<(), Box<dyn Error>> {
    let pattern = format!("{}a{}", "(".repeat(300), ")".repeat(300));
    let (authority, budget) = account(128 * 1024 * 1024)?;
    let scope = budget.enter();
    let result = parse(&pattern);
    assert!(matches!(result, Err(PredicateRegexError::Syntax(_))));
    assert!(authority.peak.load(Ordering::SeqCst) > 0);
    drop(result);
    drop(scope);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[derive(Default)]
struct AstCensus {
    nodes: u64,
    class_nodes: u64,
    // Public boxed payloads and child-vector capacities can be observed
    // without allocator instrumentation or access to private dependency fields.
    public_bytes: u64,
}

impl ast::Visitor for AstCensus {
    type Output = Self;
    type Err = Infallible;

    fn finish(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    fn visit_pre(&mut self, node: &ast::Ast) -> Result<(), Infallible> {
        use ast::Ast;
        self.nodes += 1;
        self.public_bytes += match node {
            Ast::Empty(_) | Ast::Dot(_) => size_of::<ast::Span>(),
            Ast::Flags(flags) => {
                size_of::<ast::SetFlags>()
                    + flags.flags.items.capacity() * size_of::<ast::FlagsItem>()
            }
            Ast::Literal(_) => size_of::<ast::Literal>(),
            Ast::Assertion(_) => size_of::<ast::Assertion>(),
            Ast::ClassUnicode(_) => size_of::<ast::ClassUnicode>(),
            Ast::ClassPerl(_) => size_of::<ast::ClassPerl>(),
            Ast::ClassBracketed(_) => size_of::<ast::ClassBracketed>(),
            Ast::Repetition(_) => size_of::<ast::Repetition>() + size_of::<Ast>(),
            Ast::Group(group) => {
                let name = match &group.kind {
                    ast::GroupKind::CaptureName { name, .. } => name.name.capacity(),
                    ast::GroupKind::NonCapturing(flags) => {
                        flags.items.capacity() * size_of::<ast::FlagsItem>()
                    }
                    ast::GroupKind::CaptureIndex(_) => 0,
                };
                size_of::<ast::Group>() + size_of::<Ast>() + name
            }
            Ast::Alternation(alternation) => {
                size_of::<ast::Alternation>() + alternation.asts.capacity() * size_of::<Ast>()
            }
            Ast::Concat(concat) => {
                size_of::<ast::Concat>() + concat.asts.capacity() * size_of::<Ast>()
            }
        } as u64;
        Ok(())
    }

    fn visit_class_set_item_pre(&mut self, item: &ast::ClassSetItem) -> Result<(), Infallible> {
        self.class_nodes += 1;
        self.public_bytes += match item {
            ast::ClassSetItem::Bracketed(_) => size_of::<ast::ClassBracketed>(),
            ast::ClassSetItem::Union(union) => {
                union.items.capacity() * size_of::<ast::ClassSetItem>()
            }
            _ => 0,
        } as u64;
        Ok(())
    }

    fn visit_class_set_binary_op_pre(
        &mut self,
        _: &ast::ClassSetBinaryOp,
    ) -> Result<(), Infallible> {
        self.class_nodes += 1;
        self.public_bytes += (2 * size_of::<ast::ClassSet>()) as u64;
        Ok(())
    }
}

fn hir_census(node: &hir::Hir) -> (u64, u64, u64) {
    let mut nodes = 1;
    let mut ranges = 0;
    let mut public_bytes = 0;
    match node.kind() {
        hir::HirKind::Literal(literal) => public_bytes += literal.0.len() as u64,
        hir::HirKind::Class(hir::Class::Unicode(class)) => {
            ranges += class.ranges().len() as u64;
            public_bytes += std::mem::size_of_val(class.ranges()) as u64;
        }
        hir::HirKind::Class(hir::Class::Bytes(class)) => {
            ranges += class.ranges().len() as u64;
            public_bytes += std::mem::size_of_val(class.ranges()) as u64;
        }
        hir::HirKind::Capture(capture) => {
            public_bytes += size_of::<hir::Hir>() as u64;
            public_bytes += capture.name.as_ref().map_or(0, |name| name.len()) as u64;
        }
        hir::HirKind::Repetition(_) => public_bytes += size_of::<hir::Hir>() as u64,
        hir::HirKind::Concat(children) | hir::HirKind::Alternation(children) => {
            public_bytes += (children.capacity() * size_of::<hir::Hir>()) as u64;
        }
        hir::HirKind::Empty | hir::HirKind::Look(_) => {}
    }
    for child in node.kind().subs() {
        let (child_nodes, child_ranges, child_bytes) = hir_census(child);
        nodes += child_nodes;
        ranges += child_ranges;
        public_bytes += child_bytes;
    }
    (nodes, ranges, public_bytes)
}

#[test]
fn observed_public_nodes_ranges_and_capacities_fit_source_witnesses() -> Result<(), Box<dyn Error>>
{
    let wide = format!(
        "(?:{})",
        (0..128)
            .map(|index| format!("ab{index}z"))
            .collect::<Vec<_>>()
            .join("|")
    );
    for pattern in [
        wide.as_str(),
        r"(?i)[\p{Grapheme_Base}~~\p{Age=16.0}]",
        r"(?i)[[a-z]--[[^A-Z]&&\p{Greek}]]",
        r"(?P<unicode>水{0,999})|(?-u:[\x80-\xFF])|(?i:Kſİ)",
        r"(?R:.)(?-uR:.)(?s:.)",
        r"(?:|a||b|)(?:abc|abd|abef)(?x: a # line
            b # another line
        )",
    ] {
        let witness = peak::witness(pattern)?;
        let geometry = peak::geometry(pattern)?;
        let ast = ast::parse::Parser::new().parse(pattern)?;
        let observed = ast::visit(&ast, AstCensus::default())?;
        assert!(observed.nodes <= witness.ast_nodes, "AST: {pattern}");
        assert!(
            observed.class_nodes <= witness.class_nodes,
            "class: {pattern}"
        );
        assert!(
            observed.public_bytes <= witness.ast_bytes,
            "AST storage: {pattern}"
        );

        let hir = hir::translate::TranslatorBuilder::new()
            .utf8(false)
            .build()
            .translate(pattern, &ast)?;
        let (nodes, ranges, public_bytes) = hir_census(&hir);
        assert!(nodes <= witness.hir_nodes, "HIR: {pattern}");
        assert!(ranges <= witness.ranges, "ranges: {pattern}");
        assert!(public_bytes <= geometry.hir_bytes, "HIR storage: {pattern}");
    }
    Ok(())
}

#[test]
fn rejected_multiline_error_display_keeps_its_original_private_workspace_credit()
-> Result<(), Box<dyn Error>> {
    let pattern = "(?x: a # comment\n [a-z\n";
    let (authority, budget) = account(16 * 1024 * 1024)?;
    let scope = budget.enter();
    let error = match parse(pattern) {
        Err(error) => error,
        Ok(_) => return Err("invalid multiline fixture unexpectedly parsed".into()),
    };
    let retained = authority.used.load(Ordering::SeqCst);
    let rendered = crate::owned_decode::display_string(&error)?;
    assert!(rendered.contains("error"));
    assert!(authority.used.load(Ordering::SeqCst) > retained);
    drop(rendered);
    drop(scope);
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) >= retained);
    drop(error);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[derive(Debug)]
struct ConcurrentDiagnostic {
    active: Arc<AtomicU64>,
    peak: Arc<AtomicU64>,
}

impl fmt::Display for ConcurrentDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        for _ in 0..32 {
            std::thread::yield_now();
        }
        let result = formatter.write_str("original diagnostic");
        self.active.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

impl Error for ConcurrentDiagnostic {}

#[test]
fn shared_error_serializes_its_single_private_formatter_bank() -> Result<(), Box<dyn Error>> {
    let active = Arc::new(AtomicU64::new(0));
    let peak = Arc::new(AtomicU64::new(0));
    let error = Arc::new(syntax_failure(
        ConcurrentDiagnostic {
            active: active.clone(),
            peak: peak.clone(),
        },
        None,
        None,
    ));
    let start = Arc::new(std::sync::Barrier::new(4));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let error = error.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            for _ in 0..8 {
                assert!(error.to_string().contains("original diagnostic"));
            }
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "diagnostic worker panicked")?;
    }
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    Ok(())
}
