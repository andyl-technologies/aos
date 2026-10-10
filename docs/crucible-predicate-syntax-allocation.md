# Predicate syntax allocation audit

The predicate parser admits storage before constructing the upstream AST
parser. Successful translation retains a separate HIR loan. Parser, AST,
translator, and their destruction worklists close before the temporary loan.
Syntax rejection retains the original upstream error and its loans: upstream
errors own the input pattern, and their diagnostic formatter also allocates.

This audit covers `regex-syntax = 0.8.11`, with the full default Unicode feature
set, Unicode data 16.0.0, and the dependency archive checksum recorded in the
workspace lockfile:

```text
d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4
```

The configuration is Unicode enabled, UTF-8-only matching disabled, octal
disabled, default flags, LF as line terminator, and a 250-level nesting limit.
The AST nesting limit is checked after construction; it cannot substitute for
allocation admission. Full syntax, including explicit captures, Unicode
properties, byte-mode scopes, class set operations, and counted repetitions,
remains available. Thompson construction and PikeVM search have separate
geometry based on translated HIR; they are outside this syntax audit.

## Source census

`predicate_regex/syntax/peak.rs` scans borrowed UTF-8 and byte slices. It counts
potential primitive scalar leaves; opening groups and brackets; alternation,
repetition, and class-operation punctuation; comments; property/Perl escape
pairs; ASCII class prefixes; dots; and newlines. Escaped and commented
punctuation can increase a count. It cannot remove an allocation-producing
token from the count. Case folding is potentially active only if the source
contains both `(?` and `i`; false positives reserve more storage.

Every source primitive consumes at least one scalar. Group and repetition
wrappers each require their own punctuation. Concatenation scopes are bounded
by opening groups plus alternation separators plus the root. Empty branches
use the same scope bound. Opening a group also constructs a provisional empty
child. Flag-only groups are counted separately even when that duplicates a
potential group. The AST-node bound is the sum of those individual families,
not a conversion of encoded pattern length into an assumed heap size.

The relevant allocation sites are in `src/ast/parse.rs`: `parse`,
`parse_group`, `push_or_add_alternation`, `pop_group`,
`parse_uncounted_repetition`, `parse_counted_repetition`, and the class stack
and binary-operation routines. `src/ast/mod.rs` supplies the public payload
types and `Concat::into_ast`/`Alternation::into_ast` empty-node rules.

## AST storage

All public AST payload extents use `size_of` of the pinned types. A maximum
over the complete public `Ast` payload list bounds each outer box. Nested
`Box<Ast>`, binary-operation operand boxes, bracket boxes, and union boxes are
additional named entries. Vector entries and minimum capacities are admitted
for AST child lists, class-item lists, flags, capture-name duplicate detection,
comments, parser group/class stacks, visitor stacks, and destruction worklists.
Capture/property strings, cloned capture names, comment text, and the parser
scratch string have separate byte capacities.

The parser's private `GroupState` has a `Concat`, `Group`, and boolean in its
largest payload. `ClassState` has either `ClassSetUnion` plus `ClassBracketed`,
or `ClassSetBinaryOpKind` plus `ClassSet`. The AST visitor has a stack of an AST
reference plus its private frame, and a separate `ClassInduct`/`ClassFrame`
stack. The largest AST frame carries a child reference and a slice. The largest
class frame carries the operation, left-child, and right-child references.
The implementation adds discriminant extents and alignment gaps to their
audited fields rather than treating private Rust layout as an ABI.

`Ast::drop` allocates a `Vec<Ast>` and provisional boxed empty spans.
`ClassSet::drop` allocates its own `Vec<ClassSet>`. These allocations are covered
even when nesting validation or translation rejects the source.

## Unicode ranges

The generated source tables give these finite input bounds:

| Source witness | Bound |
| --- | ---: |
| Largest single direct range table, `property_bool::GRAPHEME_BASE` | 894 |
| Sum of all 28 `age` range tables | 1,734 |
| Simple-fold source keys | 2,938 |
| Simple-fold directed target entries | 3,034 |
| Targets associated with one scalar | 3 |
| Largest ASCII class input table, `Space` | 6 |

The age bound is used for every potential Unicode property escape because
`unicode::class` can union successive age tables. Every other direct table is
smaller. `\w`, `\d`, and `\s` use the same conservative property bound. Each
literal/range contributes one input interval, a dot contributes at most three
(CRLF mode excludes two separate bytes or scalars),
and each possible negation introduces at most one additional interval.

`IntervalSet` is canonical before folding: its source intervals are disjoint.
Consequently a single fold invocation can append each directed table entry at
most once. Property, ASCII, and bracketed-class folding use the full 3,034
entry bound; folded scalar literals use the three-target bound. Byte folding
is smaller and is covered by the same envelope. Two additional intervals
cover empty/full universes and the scalar-domain discontinuity.

These values are source-coupled invariants, not adjustable operator limits.
Updating the dependency archive requires re-auditing all generated tables and
the algorithms listed here, including their feature-dependent paths.

## HIR and interval workspace

`src/hir/translate.rs` owns a private `HirFrame` with `Hir`, literal-byte vector,
Unicode/byte class, or six optional boolean flags as its payload. The largest
payload plus discriminant/alignment bounds each frame. The public `Hir`
contains boxed private `PropertiesI`; its audited fields are three optional
lengths, five `LookSet`s, three booleans, and one capture count. Field extents
and possible alignment gaps bound that box.

The HIR node bound includes primitive/wrapper nodes, literal coalescing and
empty results, and the concat/alternation wrappers introduced by common-prefix
factoring. Construction and `Hir::drop` can temporarily retain both original
and replacement empty-node properties. Both property allocations and the
destruction worklist are covered by the retained HIR loan.

`Hir::concat` rebuilds a child vector and copies/coalesces adjacent literal
bytes into `prior_lit`. `Hir::alternation` rebuilds its vector, tries scalar and
byte singleton lists, tries class unions, and can split prefix/suffix lists.
Those lists and literal byte buffers have distinct banks. Every scalar literal
requires at most four UTF-8 output bytes, regardless of how its source escape
is spelled. Capture names and property normalization buffers are additional
entries.

Property normalization admits two string buffers per potential escape:
named-value queries normalize both name and value simultaneously, and
one-letter queries retain their temporary character string while normalizing
it. Minimum byte-vector capacities are included even for one-letter names.

`src/hir/interval.rs` appends results before draining old intervals during
canonicalization, intersection, difference, and negation. Symmetric difference
also retains an intersection clone. Class conversions and age lookup can
retain another range vector, and canonicalization uses stable sorting. The
workspace has separate banks for immutable source classes, the doubled mutable
result, the doubled intersection clone, a converted/table temporary, and sort
scratch. Byte ranges use the wider Unicode-range extent as an upper bound.

For the pinned standard library's amortized `Vec` growth, the sum of capacities
is bounded by twice the sum of logical entries plus minimum-capacity storage
for every possible nonempty collection. Minimum capacity is four elements,
or eight for byte vectors. Reallocation banks include both old and new
capacities. Boxed literal bytes are separately covered during Vec-to-box
conversion. Draining ranges does not shrink capacity; the retained HIR bound
therefore covers doubled pre-canonical range storage rather than only the final
range count.

The compiler's manufactured unanchored `Hir::dot(AnyByte)` has a separate
fixed bank exported to compiler admission: one byte interval and one private
property box. Its one-item canonical sort allocates no sort scratch, and
the HIR destructor returns directly for a leaf class, without constructing a
worklist or replacement property.

## Error formatting and lifetime

`src/error.rs` constructs one span table per line, up to two populated span
sets, an annotated-pattern string, line-number strings, optional multiline
notes and their joined string, and a fixed 79-character divider. The single-line
branch constructs `Spans` twice. The admission helper includes these concrete
arrays and strings, using the original byte/newline counts and the maximum
decimal width of `usize`. A generic two-pass output encoder does not eliminate
these private allocations inside upstream `Display`.

Admission errors propagate directly with their original typed source. Syntax
errors are wrapped with the untouched upstream AST/HIR error and original
loans. Field order closes HIR or error storage before its credits. No global
allocator hook, isolated helper process, input-size heap multiplier, or
unchecked success fallback participates in the bound.

The retained error supports `Send + Sync`, so an internal formatter exclusion
serializes its upstream `Display` calls. Concurrent diagnostics share the
original private formatter bank without overlapping its allocations. This
exclusion covers only diagnostic rendering and changes no guest or matcher
state.

The tests exercise malformed and excessive nesting input, Unicode properties
and age unions, folding, nested set operations, byte-mode scopes, prefix
factoring, original pre-parser refusal, temporary-credit release, retained HIR
credit, and retained typed error credit. Differential outcomes use the pinned
ordinary byte-compatible parser as a component oracle; they do not constitute
a native deployment qualification.

The counter witness independently traverses actual public AST boxes and child
vector capacities, and actual HIR nodes, class ranges, child capacities,
literal bytes and capture names. Hostile wide alternations, Unicode age/fold
classes, nested set operations, byte scopes and multiline comments remain
within the pre-parser cardinality and storage envelopes. These public counters
check the proof's observable constituents; they are not allocator
instrumentation and do not observe private transient capacity directly. A
separate multiline rejection test formats the original typed error while its
pre-admitted private formatter workspace remains retained.
