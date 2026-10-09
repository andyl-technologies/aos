//! A small Wireshark-style display-filter language for the package index.
//!
//! The package browser's search box accepts a filter *expression* rather than
//! a plain substring: every package attribute is a queryable field, combined
//! with comparison operators and boolean connectives. The grammar is small and
//! parsed by hand (no parser-generator dependency):
//!
//! ```text
//! expr        := or
//! or          := and ( ("or" | "||") and )*
//! and         := unary ( ("and" | "&&") unary )*
//! unary       := ("not" | "!") unary | primary
//! primary     := "(" expr ")" | comparison | term
//! comparison  := FIELD OP VALUE
//! term        := WORD | STRING          (free text: any field contains it)
//! FIELD       := name | version | license | platform | size | description
//! OP          := "==" | "!=" | "~" | "contains" | ">" | "<" | ">=" | "<="
//! VALUE       := WORD | STRING
//! ```
//!
//! Examples:
//!
//! ```text
//! curl                              any field contains "curl"
//! license == MIT                    exact (case-insensitive) license
//! platform ~ linux                  any platform contains "linux"
//! size > 10MB and license != GPL    numeric size, with a boolean connective
//! name ~ lib and (size > 1MB or platform == x86_64-linux)
//! ```
//!
//! A bare word with no `FIELD OP` shape is a free-text term matching any field,
//! so the previous plain-substring search keeps working. String comparisons are
//! case-insensitive; `size` is numeric and accepts byte-size suffixes
//! (`k`/`m`/`g`, `kib`/`mib`/`gib`); `version` orders semver-aware.

use crate::db::PackageRow;

/// A parsed, evaluatable package filter expression.
///
/// Build one with [`Filter::parse`]; test a package with [`Filter::matches`].
#[derive(Debug, Clone)]
pub struct Filter {
    root: Expr,
}

/// An error describing why a filter expression failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    message: String,
}

impl FilterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FilterError {}

/// A queryable package attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Version,
    License,
    Platform,
    Size,
    Description,
}

impl Field {
    /// Resolve a field name (with a few aliases) to a [`Field`].
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "name" => Some(Self::Name),
            "version" | "latest" => Some(Self::Version),
            "license" | "licence" => Some(Self::License),
            "platform" | "platforms" => Some(Self::Platform),
            "size" | "closure" => Some(Self::Size),
            "description" | "desc" => Some(Self::Description),
            _ => None,
        }
    }
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Contains,
    Gt,
    Lt,
    Ge,
    Le,
}

/// A node in the parsed filter expression tree.
#[derive(Debug, Clone)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// A `field op value` comparison.
    Compare(Field, Op, String),
    /// A free-text term: any field contains this substring.
    Term(String),
}

/// The available filter field names, for UI hints and autocomplete.
pub const FIELD_NAMES: &[&str] = &[
    "name",
    "version",
    "license",
    "platform",
    "size",
    "description",
];

/// Maximum accepted length, in bytes, of a raw filter expression.
///
/// The `?filter=` query parameter is reachable by unauthenticated visitors, so
/// the input is rejected before tokenizing if it exceeds this bound. 4 KiB is
/// far more than any genuine filter needs, while keeping a hostile input from
/// producing a token stream large enough to drive the recursive parser into a
/// stack overflow.
const MAX_FILTER_LEN: usize = 4096;

/// Maximum nesting depth of the recursive-descent parser.
///
/// Each parenthesised group and each unary `!`/`not` descends one level; the
/// parser bails out with a [`FilterError`] once it would exceed this depth.
/// This bounds the height of the parsed [`Expr`] tree, which in turn bounds the
/// recursion of [`eval`], so neither parsing nor evaluating a hostile input can
/// overflow the worker thread's stack.
const MAX_FILTER_DEPTH: usize = 64;

impl Filter {
    /// Parse a filter expression.
    ///
    /// Returns `Ok(None)` for an empty or whitespace-only input (no filter),
    /// `Ok(Some(filter))` for a valid expression, and `Err` with a
    /// human-readable message for a malformed one.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the expression is longer than
    /// `MAX_FILTER_LEN`, is nested deeper than `MAX_FILTER_DEPTH`, or has a
    /// syntax error — an unknown operator, a missing value, an unbalanced
    /// parenthesis, or trailing tokens that do not form part of the expression.
    pub fn parse(input: &str) -> Result<Option<Self>, FilterError> {
        // Reject an over-long expression before tokenizing. This path is
        // unauthenticated, and a very long run of `(` would otherwise drive the
        // recursive-descent parser deep enough to overflow the worker stack.
        if input.len() > MAX_FILTER_LEN {
            return Err(FilterError::new("filter expression too long"));
        }
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Ok(None);
        }
        let mut parser = Parser {
            tokens,
            pos: 0,
            depth: 0,
        };
        let root = parser.parse_or()?;
        if parser.pos != parser.tokens.len() {
            return Err(FilterError::new(format!(
                "unexpected trailing input near {:?}",
                parser.tokens[parser.pos].lexeme()
            )));
        }
        Ok(Some(Self { root }))
    }

    /// Whether `pkg` satisfies the filter.
    #[must_use]
    pub fn matches(&self, pkg: &PackageRow) -> bool {
        eval(&self.root, pkg)
    }
}

/// A semver-aware sort key for a version string.
///
/// The key is `(release numbers, release-rank, original string)`: the numeric
/// runs of the part before any `-` pre-release suffix (so `1.10.0` &gt; `1.9.0`),
/// then `1` for a plain release vs `0` for a pre-release (so `1.0.0` &gt;
/// `1.0.0-rc1`), then the original string as a stable tiebreaker. A missing or
/// number-free version yields an empty number list, which sorts lowest.
#[must_use]
pub fn version_key(version: Option<&str>) -> (Vec<u64>, u8, String) {
    let raw = version.unwrap_or("");
    let (core, has_pre) = match raw.split_once('-') {
        Some((core, pre)) => (core, !pre.is_empty()),
        None => (raw, false),
    };
    let mut numbers = Vec::new();
    let mut current = String::new();
    for ch in core.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(n) = current.parse::<u64>() {
                numbers.push(n);
            }
            current.clear();
        }
    }
    if let Ok(n) = current.parse::<u64>() {
        numbers.push(n);
    }
    let release_rank = u8::from(!has_pre);
    (numbers, release_rank, raw.to_string())
}

// --- Tokenizer ---------------------------------------------------------------

/// A lexical token of a filter expression.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(Op),
    /// A bare word or quoted string (already unquoted).
    Word(String),
}

impl Token {
    /// A display form for error messages.
    fn lexeme(&self) -> String {
        match self {
            Token::LParen => "(".into(),
            Token::RParen => ")".into(),
            Token::And => "and".into(),
            Token::Or => "or".into(),
            Token::Not => "not".into(),
            Token::Op(op) => match op {
                Op::Eq => "==",
                Op::Ne => "!=",
                Op::Contains => "~",
                Op::Gt => ">",
                Op::Lt => "<",
                Op::Ge => ">=",
                Op::Le => "<=",
            }
            .into(),
            Token::Word(w) => w.clone(),
        }
    }
}

/// Characters that terminate a bare word (operators, parens, quotes).
fn is_word_boundary(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '(' | ')' | '"' | '\'' | '&' | '|' | '!' | '=' | '<' | '>' | '~'
        )
}

/// Split a filter expression into tokens.
fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '&' if chars.get(i + 1) == Some(&'&') => {
                tokens.push(Token::And);
                i += 2;
            }
            '|' if chars.get(i + 1) == Some(&'|') => {
                tokens.push(Token::Or);
                i += 2;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Op(Op::Eq));
                i += 2;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Op(Op::Ne));
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Op(Op::Ge));
                i += 2;
            }
            '<' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Op(Op::Le));
                i += 2;
            }
            '>' => {
                tokens.push(Token::Op(Op::Gt));
                i += 1;
            }
            '<' => {
                tokens.push(Token::Op(Op::Lt));
                i += 1;
            }
            '~' => {
                tokens.push(Token::Op(Op::Contains));
                i += 1;
            }
            '!' => {
                tokens.push(Token::Not);
                i += 1;
            }
            '"' | '\'' => {
                let quote = ch;
                i += 1;
                let mut value = String::new();
                while i < chars.len() && chars[i] != quote {
                    value.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(FilterError::new("unterminated quoted string"));
                }
                i += 1; // closing quote
                tokens.push(Token::Word(value));
            }
            // A lone `&`, `|`, or `=` is a boundary character that begins no
            // complete operator (`&&`, `||`, `==`); it would otherwise scan an
            // empty word and never advance `i`, hanging the tokenizer. Reject
            // it as a parse error instead (an infinite loop here would pin a
            // worker thread). `&=`, `<=`, etc. are handled by the arms above.
            '&' | '|' | '=' => {
                return Err(FilterError::new(format!(
                    "unexpected `{ch}` (did you mean `{ch}{ch}`?)"
                )));
            }
            _ => {
                let start = i;
                while i < chars.len() && !is_word_boundary(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                tokens.push(match word.to_ascii_lowercase().as_str() {
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "contains" => Token::Op(Op::Contains),
                    _ => Token::Word(word),
                });
            }
        }
    }
    Ok(tokens)
}

// --- Parser ------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Current recursion depth of the descent. Each recursive production
    /// increments this on entry (via [`Parser::enter`]) and bails out with a
    /// [`FilterError`] once it exceeds [`MAX_FILTER_DEPTH`], so a hostile,
    /// deeply-nested input cannot overflow the worker thread's stack.
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    /// Account for entering one more level of recursion.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] once the nesting depth would exceed
    /// [`MAX_FILTER_DEPTH`].
    fn enter(&mut self) -> Result<(), FilterError> {
        self.depth += 1;
        if self.depth > MAX_FILTER_DEPTH {
            return Err(FilterError::new("filter expression too deeply nested"));
        }
        Ok(())
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        self.enter()?;
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        self.enter()?;
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.pos += 1;
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, FilterError> {
        self.enter()?;
        if matches!(self.peek(), Some(Token::Not)) {
            self.pos += 1;
            let inner = self.parse_unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        let primary = self.parse_primary()?;
        self.depth -= 1;
        Ok(primary)
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        self.enter()?;
        let expr = match self.peek() {
            Some(Token::LParen) => {
                self.pos += 1;
                let inner = self.parse_or()?;
                match self.peek() {
                    Some(Token::RParen) => {
                        self.pos += 1;
                        Ok(inner)
                    }
                    _ => Err(FilterError::new("missing closing parenthesis")),
                }
            }
            Some(Token::Word(word)) => {
                let word = word.clone();
                // A `field op value` comparison if this word names a field and
                // an operator follows; otherwise a free-text term.
                let comparison = Field::parse(&word).and_then(|field| {
                    if let Some(Token::Op(op)) = self.tokens.get(self.pos + 1) {
                        Some((field, *op))
                    } else {
                        None
                    }
                });
                match comparison {
                    Some((field, op)) => {
                        self.pos += 2;
                        let value = match self.peek() {
                            Some(Token::Word(v)) => v.clone(),
                            _ => {
                                return Err(FilterError::new(format!(
                                    "expected a value after `{} {}`",
                                    word,
                                    Token::Op(op).lexeme()
                                )))
                            }
                        };
                        self.pos += 1;
                        Ok(Expr::Compare(field, op, value))
                    }
                    None => {
                        self.pos += 1;
                        Ok(Expr::Term(word))
                    }
                }
            }
            Some(other) => Err(FilterError::new(format!("unexpected `{}`", other.lexeme()))),
            None => Err(FilterError::new("unexpected end of filter")),
        }?;
        self.depth -= 1;
        Ok(expr)
    }
}

// --- Evaluator ---------------------------------------------------------------

/// Evaluate a parsed filter expression against a package.
///
/// This recurses over the [`Expr`] tree, but the tree's height is bounded by
/// the parser's [`MAX_FILTER_DEPTH`] cap (the parser refuses to build anything
/// deeper), so this recursion cannot overflow the worker thread's stack.
fn eval(expr: &Expr, pkg: &PackageRow) -> bool {
    match expr {
        Expr::Or(a, b) => eval(a, pkg) || eval(b, pkg),
        Expr::And(a, b) => eval(a, pkg) && eval(b, pkg),
        Expr::Not(a) => !eval(a, pkg),
        Expr::Term(term) => {
            let needle = term.to_lowercase();
            pkg.name.to_lowercase().contains(&needle)
                || pkg.description.to_lowercase().contains(&needle)
                || pkg.license.to_lowercase().contains(&needle)
                || pkg
                    .latest_version
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(&needle))
                || pkg
                    .platforms
                    .iter()
                    .any(|p| p.to_lowercase().contains(&needle))
        }
        Expr::Compare(field, op, value) => eval_compare(*field, *op, value, pkg),
    }
}

fn eval_compare(field: Field, op: Op, value: &str, pkg: &PackageRow) -> bool {
    match field {
        Field::Size => eval_size(op, value, pkg.closure_size),
        Field::Platform => pkg
            .platforms
            .iter()
            .any(|p| eval_string(op, value, p, false)),
        Field::Version => {
            let version = pkg.latest_version.as_deref().unwrap_or("");
            eval_string(op, value, version, true)
        }
        Field::Name => eval_string(op, value, &pkg.name, false),
        Field::License => eval_string(op, value, &pkg.license, false),
        Field::Description => eval_string(op, value, &pkg.description, false),
    }
}

/// Evaluate a string-field comparison. `version` selects semver-aware ordering
/// for the relational operators; otherwise ordering is case-insensitive
/// lexical.
fn eval_string(op: Op, value: &str, actual: &str, version: bool) -> bool {
    match op {
        Op::Eq => actual.eq_ignore_ascii_case(value),
        Op::Ne => !actual.eq_ignore_ascii_case(value),
        Op::Contains => actual.to_lowercase().contains(&value.to_lowercase()),
        Op::Gt | Op::Lt | Op::Ge | Op::Le => {
            let ordering = if version {
                version_key(Some(actual)).cmp(&version_key(Some(value)))
            } else {
                actual.to_lowercase().cmp(&value.to_lowercase())
            };
            matches_ordering(op, ordering)
        }
    }
}

/// Evaluate a numeric `size` comparison. The value may carry a byte-size
/// suffix; an unparseable value never matches.
fn eval_size(op: Op, value: &str, actual: Option<u64>) -> bool {
    let actual = actual.unwrap_or(0);
    let Some(expected) = parse_size(value) else {
        return false;
    };
    match op {
        Op::Eq => actual == expected,
        Op::Ne => actual != expected,
        // `~` on a numeric field is treated as equality.
        Op::Contains => actual == expected,
        Op::Gt | Op::Lt | Op::Ge | Op::Le => matches_ordering(op, actual.cmp(&expected)),
    }
}

/// Whether `ordering` satisfies a relational operator.
fn matches_ordering(op: Op, ordering: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::{Greater, Less};
    match op {
        Op::Gt => ordering == Greater,
        Op::Lt => ordering == Less,
        Op::Ge => ordering != Less,
        Op::Le => ordering != Greater,
        _ => false,
    }
}

/// Parse a byte size with an optional binary/decimal suffix.
///
/// Accepts a plain integer (bytes) or a number with a `k`/`m`/`g`/`t` suffix
/// (optionally `b`, `ib`, e.g. `10MB`, `512KiB`). Decimal and binary suffixes
/// are treated identically (powers of 1024), which is adequate for a filter.
fn parse_size(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(digits_end);
    let number: f64 = number.parse().ok()?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((number * multiplier) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, license: &str, version: &str, size: u64, platforms: &[&str]) -> PackageRow {
        PackageRow {
            name: name.into(),
            description: format!("the {name} package"),
            license: license.into(),
            latest_version: Some(version.into()),
            closure_size: Some(size),
            platforms: platforms.iter().map(|p| (*p).into()).collect(),
        }
    }

    fn matches(filter: &str, p: &PackageRow) -> bool {
        Filter::parse(filter).unwrap().unwrap().matches(p)
    }

    #[test]
    fn empty_filter_is_none() {
        assert!(Filter::parse("").unwrap().is_none());
        assert!(Filter::parse("   ").unwrap().is_none());
    }

    #[test]
    fn bare_term_matches_any_field() {
        let p = pkg("curl", "MIT", "8.5.0", 2_000_000, &["x86_64-linux"]);
        assert!(matches("curl", &p));
        assert!(matches("MIT", &p));
        assert!(matches("linux", &p));
        assert!(!matches("zzz", &p));
    }

    #[test]
    fn field_comparisons() {
        let p = pkg(
            "curl",
            "MIT",
            "8.5.0",
            2_000_000,
            &["x86_64-linux", "aarch64-linux"],
        );
        assert!(matches("license == MIT", &p));
        assert!(matches("license == mit", &p)); // case-insensitive
        assert!(matches("license != GPL", &p));
        assert!(matches("name ~ cur", &p));
        assert!(matches("platform ~ linux", &p));
        assert!(matches("platform == aarch64-linux", &p));
        assert!(!matches("platform == riscv64-linux", &p));
    }

    #[test]
    fn size_comparisons_with_suffixes() {
        let p = pkg("big", "MIT", "1.0.0", 10 * 1024 * 1024, &["x86_64-linux"]);
        assert!(matches("size > 1MB", &p));
        assert!(matches("size >= 10MB", &p));
        assert!(matches("size < 1GB", &p));
        assert!(!matches("size > 1GB", &p));
        // An unparseable size never matches.
        assert!(!matches("size > huge", &p));
    }

    #[test]
    fn version_comparisons_are_semver_aware() {
        let p = pkg("x", "MIT", "1.10.0", 1, &["x86_64-linux"]);
        assert!(matches("version >= 1.9.0", &p)); // 1.10 > 1.9 numerically
        assert!(matches("version > 1.9.0", &p));
        assert!(!matches("version < 1.9.0", &p));
    }

    #[test]
    fn boolean_connectives_and_precedence() {
        let p = pkg("libcurl", "MIT", "8.5.0", 2_000_000, &["x86_64-linux"]);
        assert!(matches("name ~ lib and license == MIT", &p));
        assert!(matches("name ~ lib && license == MIT", &p));
        assert!(matches("license == GPL or name ~ curl", &p));
        assert!(!matches("license == GPL and name ~ curl", &p));
        assert!(matches("not license == GPL", &p));
        assert!(matches("!(license == GPL)", &p));
        // `or` binds looser than `and`: GPL and zzz is false, or curl is true.
        assert!(matches("license == GPL and name ~ zzz or name ~ curl", &p));
        // Parentheses override precedence.
        assert!(!matches(
            "license == GPL and (name ~ zzz or name ~ curl)",
            &p
        ));
    }

    #[test]
    fn version_key_orders_numerically_not_lexically() {
        // The lexical trap: "1.9.0" > "1.10.0" as strings, but 1.10 is newer.
        assert!(version_key(Some("1.10.0")) > version_key(Some("1.9.0")));
        assert!(version_key(Some("2.0.0")) > version_key(Some("1.99.99")));
        // A missing version sorts below any real one.
        assert!(version_key(Some("0.0.1")) > version_key(None));
        // A plain release sorts above its pre-release.
        assert!(version_key(Some("1.0.0")) > version_key(Some("1.0.0-rc1")));
        // Leading non-digits (a "v" prefix) are tolerated.
        assert_eq!(version_key(Some("v1.2.3")).0, vec![1, 2, 3]);
    }

    #[test]
    fn parse_errors() {
        assert!(Filter::parse("license ==").is_err()); // missing value
        assert!(Filter::parse("(license == MIT").is_err()); // unbalanced
        assert!(Filter::parse("license == MIT)").is_err()); // trailing
        assert!(Filter::parse("\"unterminated").is_err());
    }

    #[test]
    fn lone_operator_chars_error_rather_than_hang() {
        // Regression: a lone `&`/`|`/`=` once scanned an empty word and never
        // advanced, spinning the tokenizer (and pinning a worker thread). They
        // must now parse to an error. `name = curl` (single `=`) is the easy
        // mistake to make.
        assert!(Filter::parse("name = curl").is_err());
        assert!(Filter::parse("a & b").is_err());
        assert!(Filter::parse("a | b").is_err());
        assert!(Filter::parse("=").is_err());
        // The complete two-character operators still tokenize fine.
        assert!(Filter::parse("name == curl").is_ok());
        assert!(Filter::parse("a && b").is_ok());
        assert!(Filter::parse("a || b").is_ok());
    }

    #[test]
    fn over_long_filter_is_rejected() {
        // An unauthenticated visitor could otherwise post a huge filter; reject
        // it on length before tokenizing.
        let too_long = "a".repeat(MAX_FILTER_LEN + 1);
        assert!(Filter::parse(&too_long).is_err());
        // A filter right at the cap is still accepted.
        let at_cap = "a".repeat(MAX_FILTER_LEN);
        assert!(Filter::parse(&at_cap).is_ok());
    }

    #[test]
    fn deeply_nested_filter_errors_rather_than_overflowing() {
        // Regression for the unauthenticated stack-overflow DoS (sec H6): a long
        // run of `(` once drove the recursive-descent parser past the worker
        // thread's stack. With the depth cap it must return a parse error rather
        // than panicking or overflowing — this test completing at all proves no
        // stack overflow occurred. 5000 is well past MAX_FILTER_DEPTH yet within
        // MAX_FILTER_LEN, so the depth cap (not the length cap) is exercised.
        let nested = "(".repeat(5000);
        assert!(Filter::parse(&nested).is_err());
    }

    #[test]
    fn normal_nested_filter_still_parses() {
        // A realistic nested expression stays well under the depth cap.
        assert!(Filter::parse("name ~ a and (license == MIT or platform ~ linux)").is_ok());
    }
}
