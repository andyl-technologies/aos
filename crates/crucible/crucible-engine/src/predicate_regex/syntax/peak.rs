//! Concrete allocation geometry for the pinned syntax parser and translator.
//!
//! Counts are obtained without constructing syntax. They overcount escaped or
//! commented punctuation deliberately: every actual allocation-producing token
//! is included. Public payload widths come from the dependency types. Private
//! frame bounds sum their audited field extents and every possible alignment
//! gap, rather than assuming private Rust layouts are a stable ABI.

use super::{PredicateRegexError, SyntaxFailure};
use crate::owned_decode::{DecodeAdmissionError, DecodeScratch};
use regex_syntax::{ast, hir};
use std::mem::{align_of, size_of};

// Audited in regex-syntax 0.8.11's Unicode 16.0 generated tables. Direct
// properties contain at most 894 ranges. Age alone unions successive tables;
// all 28 tables together contain 1,734 input ranges before canonicalization.
const PROPERTY_INPUT_RANGES: u64 = 1734;
const CASE_FOLD_TARGETS: u64 = 3034;
const SINGLETON_FOLD_TARGETS: u64 = 3;
const ASCII_INPUT_RANGES: u64 = 6;

pub(super) struct Geometry {
    pub(super) temporary_bytes: u64,
    pub(super) hir_bytes: u64,
}

pub(super) fn unanchored_prefix_peak() -> Result<u64, PredicateRegexError> {
    // Compiler's unanchored prefix constructs Hir::dot(AnyByte): one
    // canonical byte interval and one PropertiesI box. The one-item sort
    // does not allocate; Hir::drop returns directly for this leaf class,
    // without constructing a replacement property or a heap worklist.
    sum(&[
        properties_width()?,
        vector_bytes(1, 1, size_of::<hir::ClassBytesRange>() as u64, false)?,
    ])
}

#[cfg(test)]
pub(super) struct Witness {
    pub(super) ast_nodes: u64,
    pub(super) class_nodes: u64,
    pub(super) hir_nodes: u64,
    pub(super) ranges: u64,
    pub(super) ast_bytes: u64,
}

#[cfg(test)]
pub(super) fn witness(pattern: &str) -> Result<Witness, PredicateRegexError> {
    let census = Census::scan(pattern);
    let nodes = census.ast_nodes()?;
    Ok(Witness {
        ast_nodes: nodes,
        class_nodes: sum(&[
            census.scalars,
            census.brackets,
            mul(census.class_operators, 3)?,
            1,
        ])?,
        hir_nodes: hir_node_bound(census, nodes)?,
        ranges: census.range_inputs()?,
        ast_bytes: ast_geometry(census, nodes)?,
    })
}

#[derive(Clone, Copy, Default)]
struct Census {
    bytes: u64,
    scalars: u64,
    groups: u64,
    alternations: u64,
    repetitions: u64,
    brackets: u64,
    class_operators: u64,
    comments: u64,
    properties: u64,
    ascii_classes: u64,
    dots: u64,
    newlines: u64,
    fold_possible: bool,
}

impl Census {
    fn scan(pattern: &str) -> Self {
        let bytes = pattern.as_bytes();
        let mut census = Self {
            bytes: bytes.len() as u64,
            scalars: pattern.chars().count() as u64,
            fold_possible: pattern.contains("(?") && bytes.contains(&b'i'),
            ..Self::default()
        };
        for &byte in bytes {
            match byte {
                b'(' => census.groups += 1,
                b'|' => census.alternations += 1,
                b'*' | b'+' | b'?' | b'{' => census.repetitions += 1,
                b'[' => census.brackets += 1,
                b'&' | b'-' | b'~' => census.class_operators += 1,
                b'#' => census.comments += 1,
                b'.' => census.dots += 1,
                b'\n' => census.newlines += 1,
                _ => {}
            }
        }
        for pair in bytes.windows(2) {
            if pair[0] == b'\\'
                && matches!(
                    pair[1],
                    b'p' | b'P' | b'w' | b'W' | b'd' | b'D' | b's' | b'S'
                )
            {
                census.properties += 1;
            }
            if pair == b"[:" {
                census.ascii_classes += 1;
            }
        }
        census
    }

    fn concat_scopes(self) -> Result<u64, PredicateRegexError> {
        sum(&[self.groups, self.alternations, 1])
    }

    fn ast_nodes(self) -> Result<u64, PredicateRegexError> {
        // Primitive leaves, wrappers, alternation/concat roots, empty branches,
        // provisional empty group children, and flag-only groups are distinct.
        sum(&[
            self.scalars,
            self.groups,
            self.repetitions,
            self.brackets,
            self.alternations,
            self.concat_scopes()?,
            self.concat_scopes()?,
            self.groups,
            self.groups,
        ])
    }

    fn range_inputs(self) -> Result<u64, PredicateRegexError> {
        let classes = sum(&[self.brackets, self.properties, self.ascii_classes])?;
        let fold = if self.fold_possible {
            sum(&[
                mul(classes, CASE_FOLD_TARGETS)?,
                mul(self.scalars, SINGLETON_FOLD_TARGETS)?,
            ])?
        } else {
            0
        };
        sum(&[
            self.scalars, // Literal/range endpoints, including byte classes.
            self.scalars, // Each negation introduces at most one new interval.
            mul(self.properties, PROPERTY_INPUT_RANGES)?,
            mul(self.ascii_classes, ASCII_INPUT_RANGES)?,
            mul(self.dots, 3)?, // CRLF mode excludes two separate scalars/bytes.
            fold,
            2, // Empty/full universe and the Unicode surrogate discontinuity.
        ])
    }
}

pub(super) fn geometry(pattern: &str) -> Result<Geometry, PredicateRegexError> {
    let census = Census::scan(pattern);
    let nodes = census.ast_nodes()?;
    let classes = sum(&[census.scalars, census.brackets, census.properties, 1])?;
    let hir_nodes = hir_node_bound(census, nodes)?;
    let ranges = census.range_inputs()?;
    let literal_bytes = mul(census.scalars, 4)?;

    let hir_bytes = sum(&[
        mul(mul(hir_nodes, 2)?, properties_width()?)?,
        mul(
            sum(&[census.groups, census.repetitions])?,
            size_of::<hir::Hir>() as u64,
        )?,
        vector_bytes(hir_nodes, hir_nodes, size_of::<hir::Hir>() as u64, false)?,
        // Canonicalization drains but never shrinks its allocation. A class
        // can retain the capacity of its doubled pre-canonical range buffer.
        vector_bytes(
            mul(ranges, 2)?,
            classes,
            size_of::<hir::ClassUnicodeRange>() as u64,
            false,
        )?,
        literal_bytes,
        census.bytes, // Capture names moved into boxed strings.
        vector_bytes(hir_nodes, 1, size_of::<hir::Hir>() as u64, true)?, // HIR Drop worklist.
    ])?;

    let ast_bytes = ast_geometry(census, nodes)?;
    let hir_temporary = sum(&[
        // Translator, old/new simplification lists, and prefix/suffix lists.
        vector_bytes(hir_nodes, 1, hir_frame_width()?, true)?,
        vector_bytes(hir_nodes, hir_nodes, size_of::<hir::Hir>() as u64, true)?,
        vector_bytes(hir_nodes, hir_nodes, size_of::<hir::Hir>() as u64, true)?,
        vector_bytes(hir_nodes, hir_nodes, size_of::<hir::Hir>() as u64, true)?,
        // A removed HIR node may coexist with its empty replacement's boxed properties.
        mul(hir_nodes, properties_width()?)?,
        interval_workspace(ranges, classes)?,
        vector_bytes(literal_bytes, hir_nodes, 1, true)?, // Translator literal accumulation.
        vector_bytes(literal_bytes, hir_nodes, 1, true)?, // Concat prior_lit accumulation.
        literal_bytes,                                    // Vec-to-box shrink/copy overlap.
        vector_bytes(hir_nodes, 1, size_of::<char>() as u64, true)?, // singleton_chars.
        vector_bytes(hir_nodes, 1, 1, true)?,             // singleton_bytes.
        // Named-value lookup normalizes two strings at once. One-letter
        // lookup also retains its char-to-String source while normalizing.
        vector_bytes(census.bytes, mul(census.properties, 2)?, 1, true)?,
    ])?;
    let error_bytes = sum(&[
        census.bytes, // Both upstream error types own the complete pattern.
        size_of::<SyntaxFailure<ast::Error>>() as u64,
        size_of::<SyntaxFailure<hir::Error>>() as u64,
        error_formatter_geometry(census)?,
    ])?;
    Ok(Geometry {
        temporary_bytes: sum(&[ast_bytes, hir_temporary, error_bytes])?,
        hir_bytes,
    })
}

fn hir_node_bound(census: Census, ast_nodes: u64) -> Result<u64, PredicateRegexError> {
    sum(&[
        ast_nodes,
        mul(census.alternations, 3)?, // Prefix factoring's concat/alt wrappers.
        mul(census.concat_scopes()?, 2)?, // Literal coalescing and empty roots.
        1,
    ])
}

fn error_formatter_geometry(census: Census) -> Result<u64, PredicateRegexError> {
    // error::Formatter is allocation-producing even in a Display count pass.
    // Its single-line branch constructs Spans twice; each has one Vec per
    // line and at most two error spans. Reserve those private buffers too.
    let digits = u64::from(usize::MAX.ilog10()) + 1;
    let lines = sum(&[census.newlines, 1])?;
    let padding = sum(&[digits, 4])?;
    let annotation = sum(&[
        census.bytes,
        mul(lines, padding)?,
        mul(sum(&[census.bytes, padding])?, 2)?,
    ])?;
    let note = sum(&[64, mul(digits, 4)?])?;
    sum(&[
        mul(mul(lines, 2)?, size_of::<Vec<ast::Span>>() as u64)?,
        vector_bytes(4, 6, size_of::<ast::Span>() as u64, true)?,
        vector_bytes(annotation, 1, 1, true)?,
        vector_bytes(sum(&[census.bytes, padding])?, 1, 1, true)?,
        vector_bytes(note, 2, 1, true)?, // At most two multiline notes.
        vector_bytes(sum(&[mul(note, 2)?, 1])?, 1, 1, true)?, // notes.join.
        vector_bytes(2, 1, size_of::<String>() as u64, true)?,
        vector_bytes(digits, 2, 1, true)?, // Decimal and padded line numbers.
        vector_bytes(79, 1, 1, true)?,     // Multiline divider's fixed 79 characters.
    ])
}

fn ast_geometry(census: Census, nodes: u64) -> Result<u64, PredicateRegexError> {
    let payload = [
        size_of::<ast::Span>(),
        size_of::<ast::SetFlags>(),
        size_of::<ast::Literal>(),
        size_of::<ast::Assertion>(),
        size_of::<ast::ClassUnicode>(),
        size_of::<ast::ClassPerl>(),
        size_of::<ast::ClassBracketed>(),
        size_of::<ast::Repetition>(),
        size_of::<ast::Group>(),
        size_of::<ast::Alternation>(),
        size_of::<ast::Concat>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0) as u64;
    let class_nodes = sum(&[
        census.scalars,
        census.brackets,
        mul(census.class_operators, 3)?,
        1,
    ])?;
    sum(&[
        mul(nodes, payload)?,
        mul(
            sum(&[census.groups, census.repetitions])?,
            size_of::<ast::Ast>() as u64,
        )?,
        mul(census.brackets, size_of::<ast::ClassBracketed>() as u64)?,
        mul(
            census.class_operators,
            size_of::<ast::ClassSetBinaryOp>() as u64,
        )?,
        mul(
            mul(census.class_operators, 2)?,
            size_of::<ast::ClassSet>() as u64,
        )?,
        mul(
            sum(&[census.brackets, mul(census.class_operators, 2)?, 1])?,
            size_of::<ast::ClassSetUnion>() as u64,
        )?,
        vector_bytes(
            nodes,
            census.concat_scopes()?,
            size_of::<ast::Ast>() as u64,
            true,
        )?,
        vector_bytes(
            class_nodes,
            class_nodes,
            size_of::<ast::ClassSetItem>() as u64,
            true,
        )?,
        vector_bytes(
            sum(&[census.groups, census.alternations])?,
            1,
            group_frame_width()?,
            true,
        )?,
        vector_bytes(
            sum(&[census.brackets, census.class_operators])?,
            1,
            class_frame_width()?,
            true,
        )?,
        vector_bytes(census.groups, 1, size_of::<ast::CaptureName>() as u64, true)?,
        vector_bytes(
            census.scalars,
            census.groups,
            size_of::<ast::FlagsItem>() as u64,
            true,
        )?,
        vector_bytes(census.comments, 1, size_of::<ast::Comment>() as u64, true)?,
        vector_bytes(census.bytes, census.comments, 1, true)?, // Comment text.
        census.bytes,                                          // AST capture/property names.
        census.bytes, // Capture-name duplicate detector's owned names.
        vector_bytes(census.bytes, 1, 1, true)?, // Parser scratch String.
        vector_bytes(nodes, 1, ast_visitor_width()?, true)?,
        vector_bytes(class_nodes, 1, class_visitor_width()?, true)?,
        vector_bytes(nodes, 1, size_of::<ast::Ast>() as u64, true)?, // Iterative AST Drop.
        vector_bytes(class_nodes, 1, size_of::<ast::ClassSet>() as u64, true)?, // ClassSet Drop.
        mul(nodes, size_of::<ast::Span>() as u64)?, // Drop's provisional empty nodes.
        size_of::<ast::parse::Parser>() as u64,
        size_of::<hir::translate::Translator>() as u64,
        size_of::<Option<DecodeScratch>>() as u64,
    ])
}

fn interval_workspace(ranges: u64, classes: u64) -> Result<u64, PredicateRegexError> {
    let width = size_of::<hir::ClassUnicodeRange>() as u64;
    sum(&[
        vector_bytes(ranges, classes, width, false)?, // Immutable source classes.
        vector_bytes(mul(ranges, 2)?, 1, width, true)?, // Append-then-drain mutable result.
        vector_bytes(mul(ranges, 2)?, 1, width, true)?, // Symmetric-difference intersection clone.
        vector_bytes(ranges, 1, width, true)?, // Byte/Unicode conversion or age-table temporary.
        mul(mul(ranges, 2)?, width)?,          // Stable sort's temporary interval array.
    ])
}

// Each public type's actual extent is retained. For a private struct, n+1
// maximum-alignment gaps cover all field reorderings plus leading/trailing
// padding. Private enum widths add an integer discriminant and another gap.
fn properties_width() -> Result<u64, PredicateRegexError> {
    fields(&[
        size_of::<Option<usize>>(),
        size_of::<Option<usize>>(),
        size_of::<hir::LookSet>(),
        size_of::<hir::LookSet>(),
        size_of::<hir::LookSet>(),
        size_of::<hir::LookSet>(),
        size_of::<hir::LookSet>(),
        size_of::<bool>(),
        size_of::<usize>(),
        size_of::<Option<usize>>(),
        size_of::<bool>(),
        size_of::<bool>(),
    ])
}

fn hir_frame_width() -> Result<u64, PredicateRegexError> {
    let payload = [
        size_of::<hir::Hir>(),
        size_of::<Vec<u8>>(),
        size_of::<hir::ClassUnicode>(),
        size_of::<hir::ClassBytes>(),
        size_of::<[Option<bool>; 6]>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    fields(&[payload, size_of::<usize>()])
}

fn group_frame_width() -> Result<u64, PredicateRegexError> {
    fields(&[
        size_of::<ast::Concat>(),
        size_of::<ast::Group>(),
        size_of::<bool>(),
        size_of::<usize>(),
    ])
}

fn class_frame_width() -> Result<u64, PredicateRegexError> {
    let open = fields(&[
        size_of::<ast::ClassSetUnion>(),
        size_of::<ast::ClassBracketed>(),
    ])?;
    let op = fields(&[
        size_of::<ast::ClassSetBinaryOpKind>(),
        size_of::<ast::ClassSet>(),
    ])?;
    sum(&[open.max(op), (2 * size_of::<usize>()) as u64])
}

fn ast_visitor_width() -> Result<u64, PredicateRegexError> {
    fields(&[
        size_of::<&ast::Ast>(),
        size_of::<&ast::Ast>(),
        size_of::<&[ast::Ast]>(),
        size_of::<usize>(),
    ])
}

fn class_visitor_width() -> Result<u64, PredicateRegexError> {
    // ClassInduct carries a reference/discriminant; ClassFrame's largest
    // BinaryLHS payload carries three references plus its discriminant.
    fields(&[
        size_of::<&ast::ClassSet>(),
        size_of::<usize>(),
        size_of::<&ast::ClassSetBinaryOp>(),
        size_of::<&ast::ClassSet>(),
        size_of::<&ast::ClassSet>(),
        size_of::<usize>(),
    ])
}

fn fields(widths: &[usize]) -> Result<u64, PredicateRegexError> {
    let padding = mul((widths.len() + 1) as u64, align_of::<usize>() as u64)?;
    widths
        .iter()
        .try_fold(padding, |total, width| sum(&[total, *width as u64]))
}

fn vector_bytes(
    entries: u64,
    collections: u64,
    width: u64,
    reallocating: bool,
) -> Result<u64, PredicateRegexError> {
    // RawVec's pinned grow_amortized doubles capacity, with minimum four
    // elements (eight for bytes). Include the old allocation during growth.
    let minimum = if width == 1 { 8 } else { 4 };
    let capacity = sum(&[mul(entries, 2)?, mul(collections, minimum)?])?;
    mul(mul(capacity, if reallocating { 2 } else { 1 })?, width)
}

fn sum(values: &[u64]) -> Result<u64, PredicateRegexError> {
    values.iter().try_fold(0_u64, |total, value| {
        total.checked_add(*value).ok_or_else(overflow)
    })
}

fn mul(left: u64, right: u64) -> Result<u64, PredicateRegexError> {
    left.checked_mul(right).ok_or_else(overflow)
}

fn overflow() -> PredicateRegexError {
    PredicateRegexError::Admission(DecodeAdmissionError::new(GeometryOverflow))
}

#[derive(Debug)]
struct GeometryOverflow;

impl std::fmt::Display for GeometryOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("predicate syntax allocation geometry overflow")
    }
}

impl std::error::Error for GeometryOverflow {}
