//! POSIX ERE bracket-expression translation for the Rust `regex` engine.
//!
//! `builtins.match` / `builtins.split` patterns are POSIX extended regular
//! expressions evaluated by C++ Nix through `std::regex` with the
//! `extended` flag, i.e. GNU libstdc++'s ERE compiler on Linux. The Rust
//! `regex` crate's syntax diverges from POSIX ERE *inside bracket
//! expressions*: POSIX treats `\` as an ordinary member (it never escapes
//! inside `[...]`), allows `]` as the first member, treats `[`, `&&`, `~~`
//! and `--` literally, and supports `[.x.]` collating symbols and `[=x=]`
//! equivalence classes. Passing the pattern through verbatim therefore
//! mis-parses classes such as `[a-zA-Z0-9@%:_.\-]`, where POSIX includes a
//! literal backslash but Rust's `\-` escape does not.
//!
//! This module re-parses every bracket expression with libstdc++'s exact
//! grammar (GCC 14 `bits/regex_scanner.tcc` `_M_scan_in_bracket` and
//! `bits/regex_compiler.tcc` `_M_expression_term`) and re-emits it in Rust
//! `regex` class syntax with every literal member hex-escaped. Bytes outside
//! bracket expressions are copied verbatim. The reference semantics,
//! verified against the libstdc++ sources and a C++ Nix 2.24 oracle:
//!
//! ```text
//! [\]      backslash is an ordinary member (and a valid range endpoint)
//! []a]     `]` first (after optional `^`) is an ordinary member
//! [a[b]    `[` not followed by `.`/`:`/`=` is an ordinary member
//! [-a] [a-] [--0]   leading/trailing dash is literal; leading dash may
//!                   still start a range (`[--0]` is the range `-`..`0`)
//! [a--]    `x--` is the range `x`..`-`
//! [z-a]    reversed ranges are an error (libstdc++ `error_range`)
//! [a-z-0]  a dash after a completed range is an error in POSIX mode
//! [[:alpha:]-z]  a dash after a class is an error (`error_range`)
//! [[:d:]]  class names are case-folded; `d`/`s`/`w` are GNU extensions
//! [[.hyphen.]]   collating symbols resolve via the portable character set
//! [[=a=]]  equivalence classes case-fold their (single) collating element
//! ```
//!
//! Ranges compare their endpoints as *signed* `char` (libstdc++ compiles
//! `std::regex<char>` with `char` signed on x86), so a range whose low
//! endpoint is `>= 0x80` and high endpoint is `< 0x80` is valid and denotes
//! the union of two byte ranges.

/// A parsed member of a POSIX bracket expression.
enum BracketElement {
    /// A single literal byte member.
    Byte(u8),
    /// An inclusive byte range, already validated (signed `lo <= hi`).
    Range(u8, u8),
    /// A named POSIX character class, in Rust `regex` spelling.
    CharClass(&'static str),
}

/// Parser state mirroring libstdc++'s `_BracketState`: the previously seen
/// term, which decides how a following `-` is interpreted.
#[derive(Clone, Copy)]
enum LastTerm {
    /// Nothing cached (bracket start, or a just-completed range).
    None,
    /// A cached ordinary character that may become a range's low endpoint.
    Char(u8),
    /// A class-like term (`[:...:]` or `[=...=]`); cannot start a range.
    Class,
}

/// The POSIX portable character set collating-symbol names, indexed by
/// character code, as hard-coded in libstdc++'s
/// `regex_traits::lookup_collatename` (GCC 14 `bits/regex.tcc`).
const COLLATE_NAMES: [&str; 128] = [
    "NUL",
    "SOH",
    "STX",
    "ETX",
    "EOT",
    "ENQ",
    "ACK",
    "alert",
    "backspace",
    "tab",
    "newline",
    "vertical-tab",
    "form-feed",
    "carriage-return",
    "SO",
    "SI",
    "DLE",
    "DC1",
    "DC2",
    "DC3",
    "DC4",
    "NAK",
    "SYN",
    "ETB",
    "CAN",
    "EM",
    "SUB",
    "ESC",
    "IS4",
    "IS3",
    "IS2",
    "IS1",
    "space",
    "exclamation-mark",
    "quotation-mark",
    "number-sign",
    "dollar-sign",
    "percent-sign",
    "ampersand",
    "apostrophe",
    "left-parenthesis",
    "right-parenthesis",
    "asterisk",
    "plus-sign",
    "comma",
    "hyphen",
    "period",
    "slash",
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "colon",
    "semicolon",
    "less-than-sign",
    "equals-sign",
    "greater-than-sign",
    "question-mark",
    "commercial-at",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "left-square-bracket",
    "backslash",
    "right-square-bracket",
    "circumflex",
    "underscore",
    "grave-accent",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "left-curly-bracket",
    "vertical-line",
    "right-curly-bracket",
    "tilde",
    "DEL",
];

/// POSIX character-class names accepted by libstdc++'s `lookup_classname`,
/// mapped to their Rust `regex` ASCII-class spelling. Lookup is performed on
/// the case-folded name; `d`, `s` and `w` are GNU extensions equivalent to
/// `digit`, `space` and `alnum`+`_` respectively.
const CLASS_NAMES: [(&str, &str); 15] = [
    ("d", "digit"),
    ("w", "word"),
    ("s", "space"),
    ("alnum", "alnum"),
    ("alpha", "alpha"),
    ("blank", "blank"),
    ("cntrl", "cntrl"),
    ("digit", "digit"),
    ("graph", "graph"),
    ("lower", "lower"),
    ("print", "print"),
    ("punct", "punct"),
    ("space", "space"),
    ("upper", "upper"),
    ("xdigit", "xdigit"),
];

/// Translates a POSIX ERE pattern into Rust `regex` syntax.
///
/// Bytes outside bracket expressions are copied verbatim (their grammar is
/// shared between the engines once the unsupported-construct validation in
/// `validate_match_regex_pattern` has passed); every bracket expression is
/// re-parsed with POSIX semantics and re-emitted with hex-escaped members.
///
/// # Errors
///
/// Returns a human-readable message for the pattern classes libstdc++
/// rejects: unterminated bracket expressions, invalid or reversed ranges,
/// misplaced dashes, unknown character-class names, and unknown collating
/// symbols or equivalence classes.
pub(crate) fn translate_posix_ere(pattern: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(pattern.len());
    let mut index = 0;
    while index < pattern.len() {
        match pattern[index] {
            b'\\' => {
                // Outside brackets, an escape consumes the next byte; both
                // are copied verbatim (unsupported escapes were rejected by
                // the pattern validator).
                out.push(b'\\');
                if let Some(&escaped) = pattern.get(index + 1) {
                    out.push(escaped);
                    index += 2;
                } else {
                    return Err("trailing backslash in regular expression".to_owned());
                }
            }
            b'[' => index = translate_bracket_expression(pattern, index, &mut out)?,
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Ok(out)
}

/// Returns the index of the `]` closing the bracket expression opening at
/// `open`, or `None` when the expression is unterminated.
///
/// This is the lexical rule from libstdc++'s `_M_scan_in_bracket`: a `]`
/// directly after `[` or `[^` is an ordinary member, and the bodies of
/// `[. .]`, `[: :]` and `[= =]` terms are opaque.
pub(crate) fn bracket_expression_end(pattern: &[u8], open: usize) -> Option<usize> {
    let mut index = open + 1;
    if pattern.get(index) == Some(&b'^') {
        index += 1;
    }
    if pattern.get(index) == Some(&b']') {
        index += 1;
    }
    loop {
        match *pattern.get(index)? {
            b']' => return Some(index),
            b'[' if matches!(pattern.get(index + 1), Some(b'.' | b':' | b'=')) => {
                let delimiter = pattern[index + 1];
                let mut cursor = index + 2;
                loop {
                    if *pattern.get(cursor)? == delimiter && pattern.get(cursor + 1) == Some(&b']')
                    {
                        break;
                    }
                    cursor += 1;
                }
                index = cursor + 2;
            }
            _ => index += 1,
        }
    }
}

/// Parses one bracket expression starting at `open` (pointing at `[`),
/// appends its Rust `regex` translation to `out`, and returns the index one
/// past the closing `]`.
fn translate_bracket_expression(
    pattern: &[u8],
    open: usize,
    out: &mut Vec<u8>,
) -> Result<usize, String> {
    const UNTERMINATED: &str = "unterminated bracket expression";
    let mut index = open + 1;
    let mut negated = false;
    if pattern.get(index) == Some(&b'^') {
        negated = true;
        index += 1;
    }

    let mut elements: Vec<BracketElement> = Vec::new();
    let mut last = LastTerm::None;
    let mut at_start = true;
    let flush = |last: &mut LastTerm, elements: &mut Vec<BracketElement>| {
        if let LastTerm::Char(byte) = *last {
            elements.push(BracketElement::Byte(byte));
        }
        *last = LastTerm::None;
    };

    loop {
        let Some(&byte) = pattern.get(index) else {
            return Err(UNTERMINATED.to_owned());
        };
        match byte {
            b']' if !at_start => {
                flush(&mut last, &mut elements);
                index += 1;
                break;
            }
            b'[' if matches!(pattern.get(index + 1), Some(b'.' | b':' | b'=')) => {
                let delimiter = pattern[index + 1];
                let (content, after) = bracket_term_content(pattern, index + 2, delimiter)
                    .ok_or_else(|| UNTERMINATED.to_owned())?;
                match delimiter {
                    b':' => {
                        flush(&mut last, &mut elements);
                        elements.push(BracketElement::CharClass(lookup_class_name(content)?));
                        last = LastTerm::Class;
                    }
                    b'.' => {
                        let symbol = lookup_collate_name(content).ok_or_else(|| {
                            format!(
                                "invalid collating element '[.{}.]'",
                                String::from_utf8_lossy(content)
                            )
                        })?;
                        // A single-char collating symbol behaves exactly
                        // like an ordinary character (it may start a range).
                        flush(&mut last, &mut elements);
                        last = LastTerm::Char(symbol);
                    }
                    _ => {
                        let symbol = lookup_collate_name(content).ok_or_else(|| {
                            format!(
                                "invalid equivalence class '[={}=]'",
                                String::from_utf8_lossy(content)
                            )
                        })?;
                        flush(&mut last, &mut elements);
                        // libstdc++ matches equivalence classes through
                        // `transform_primary`, which case-folds in the "C"
                        // locale: `[=a=]` matches both `a` and `A`.
                        elements.push(BracketElement::Byte(symbol.to_ascii_lowercase()));
                        if symbol.is_ascii_alphabetic() {
                            elements.push(BracketElement::Byte(symbol.to_ascii_uppercase()));
                        }
                        last = LastTerm::Class;
                    }
                }
                index = after;
            }
            b'-' if !at_start => {
                match pattern.get(index + 1) {
                    None => return Err(UNTERMINATED.to_owned()),
                    Some(b']') => {
                        // A dash immediately before the closing `]` is a
                        // literal member.
                        flush(&mut last, &mut elements);
                        elements.push(BracketElement::Byte(b'-'));
                        index += 2;
                        break;
                    }
                    Some(&next) => match last {
                        LastTerm::Class => {
                            return Err(
                                "invalid start of range in bracket expression".to_owned()
                            );
                        }
                        LastTerm::None => {
                            return Err(
                                "invalid location of '-' in bracket expression".to_owned()
                            );
                        }
                        LastTerm::Char(low) => {
                            if next == b'['
                                && matches!(pattern.get(index + 2), Some(b'.' | b':' | b'='))
                            {
                                return Err(
                                    "invalid end of range in bracket expression".to_owned()
                                );
                            }
                            // `x--` is the range `x`..`-`; any other byte
                            // (including `\` and a bare `[`) is an ordinary
                            // high endpoint.
                            if (low as i8) > (next as i8) {
                                return Err("invalid range in bracket expression".to_owned());
                            }
                            elements.push(BracketElement::Range(low, next));
                            last = LastTerm::None;
                            index += 2;
                        }
                    },
                }
            }
            _ => {
                // Ordinary member: any byte, including `\`, `]` at the
                // start position, a bare `[`, `^` past the start, and `-`
                // as the very first member (which may still begin a range).
                flush(&mut last, &mut elements);
                last = LastTerm::Char(byte);
                index += 1;
            }
        }
        at_start = false;
    }

    out.push(b'[');
    if negated {
        out.push(b'^');
    }
    for element in &elements {
        match *element {
            BracketElement::Byte(byte) => push_class_byte(out, byte),
            BracketElement::Range(low, high) => {
                // Endpoints were compared as signed `char`; a sign-crossing
                // range denotes the union of two unsigned byte ranges.
                if (low as i8) < 0 && (high as i8) >= 0 {
                    push_class_byte(out, 0x00);
                    out.push(b'-');
                    push_class_byte(out, high);
                    push_class_byte(out, low);
                    out.push(b'-');
                    push_class_byte(out, 0xFF);
                } else {
                    push_class_byte(out, low);
                    out.push(b'-');
                    push_class_byte(out, high);
                }
            }
            BracketElement::CharClass(name) => {
                out.push(b'[');
                out.push(b':');
                out.extend_from_slice(name.as_bytes());
                out.push(b':');
                out.push(b']');
            }
        }
    }
    out.push(b']');
    Ok(index)
}

/// Returns the body of a `[. .]` / `[: :]` / `[= =]` term starting at
/// `start` (one past the opening delimiter) together with the index one past
/// the closing `X]`, or `None` when the term is unterminated.
fn bracket_term_content(pattern: &[u8], start: usize, delimiter: u8) -> Option<(&[u8], usize)> {
    let mut cursor = start;
    loop {
        if *pattern.get(cursor)? == delimiter && pattern.get(cursor + 1) == Some(&b']') {
            return Some((&pattern[start..cursor], cursor + 2));
        }
        cursor += 1;
    }
}

/// Resolves a `[: :]` class name to its Rust `regex` spelling, case-folding
/// the name first as libstdc++'s `lookup_classname` does.
fn lookup_class_name(content: &[u8]) -> Result<&'static str, String> {
    let folded = content.to_ascii_lowercase();
    CLASS_NAMES
        .iter()
        .find(|(name, _)| name.as_bytes() == folded.as_slice())
        .map(|&(_, rust_name)| rust_name)
        .ok_or_else(|| {
            format!(
                "invalid character class '[:{}:]'",
                String::from_utf8_lossy(content)
            )
        })
}

/// Resolves a collating-symbol or equivalence-class body to its character
/// via the portable character set table; multi-character collating elements
/// and unknown names are rejected exactly as libstdc++'s
/// `lookup_collatename` (which returns an empty string, turning into
/// `error_collate`).
fn lookup_collate_name(content: &[u8]) -> Option<u8> {
    COLLATE_NAMES
        .iter()
        .position(|name| name.as_bytes() == content)
        .map(|code| code as u8)
}

/// Appends one literal class member, hex-escaping every byte that is not
/// alphanumeric so that Rust `regex` metacharacters (`\`, `]`, `^`, `&&`,
/// `~~`, `--`, nested `[`) cannot be re-interpreted.
fn push_class_byte(out: &mut Vec<u8>, byte: u8) {
    if byte.is_ascii_alphanumeric() {
        out.push(byte);
    } else {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        out.push(b'\\');
        out.push(b'x');
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0F)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translate(pattern: &str) -> String {
        let translated =
            translate_posix_ere(pattern.as_bytes()).expect("pattern translates cleanly");
        String::from_utf8(translated).expect("translated pattern is UTF-8")
    }

    fn translate_err(pattern: &str) -> String {
        translate_posix_ere(pattern.as_bytes()).expect_err("pattern is rejected")
    }

    #[test]
    fn passes_through_non_bracket_syntax() {
        assert_eq!(translate(r"a(b|c)*\.d{1,2}"), r"a(b|c)*\.d{1,2}");
    }

    #[test]
    fn backslash_is_a_literal_member_inside_brackets() {
        // The lib/hardening.nix systemd unit-name class: `\` is a member,
        // the trailing `-` is literal.
        assert_eq!(
            translate(r"[a-zA-Z0-9@%:_.\-]+"),
            r"[a-zA-Z0-9\x40\x25\x3A\x5F\x2E\x5C\x2D]+"
        );
        assert_eq!(translate(r"[\]"), r"[\x5C]");
        // `[\d]` is the two members `\` and `d`, not a digit class.
        assert_eq!(translate(r"[\d]"), r"[\x5Cd]");
    }

    #[test]
    fn backslash_can_be_a_range_endpoint() {
        // `[a\-b]` parses as `a`, then the range `\`..`b`.
        assert_eq!(translate(r"[a\-b]"), r"[a\x5C-b]");
    }

    #[test]
    fn right_bracket_is_literal_at_start() {
        assert_eq!(translate("[]a]"), r"[\x5Da]");
        assert_eq!(translate("[^]a]"), r"[^\x5Da]");
        assert_eq!(translate("[]-a]"), r"[\x5D-a]");
    }

    #[test]
    fn dash_placement_rules() {
        assert_eq!(translate("[-a]"), r"[\x2Da]");
        assert_eq!(translate("[a-]"), r"[a\x2D]");
        assert_eq!(translate("[--0]"), r"[\x2D-0]");
        // `x--` is the range `x`..`-`.
        assert_eq!(translate("[+--]"), r"[\x2B-\x2D]");
        assert_eq!(translate("[---]"), r"[\x2D-\x2D]");
        assert_eq!(translate("[----]"), r"[\x2D-\x2D\x2D]");
        assert!(translate_err("[-----]").contains("invalid location of '-'"));
        // A dash after a completed range or a class cannot start another.
        assert!(translate_err("[a-z-0]").contains("invalid location of '-'"));
        assert!(translate_err("[[:alpha:]-z]").contains("invalid start of range"));
        // Reversed ranges are `error_range`, not an empty set.
        assert!(translate_err("[z-a]").contains("invalid range"));
        assert!(translate_err("[a--b]").contains("invalid range"));
        assert!(translate_err("[a-[.z.]]").contains("invalid end of range"));
    }

    #[test]
    fn literal_left_bracket_and_set_operators() {
        assert_eq!(translate("[a[b]"), r"[a\x5Bb]");
        assert_eq!(translate("[a&&b]"), r"[a\x26\x26b]");
        assert_eq!(translate("[a~~b]"), r"[a\x7E\x7Eb]");
        assert_eq!(translate("[a^]"), r"[a\x5E]");
    }

    #[test]
    fn character_classes_fold_and_map_names() {
        assert_eq!(translate("[[:alpha:]]"), "[[:alpha:]]");
        assert_eq!(translate("[[:ALPHA:]]"), "[[:alpha:]]");
        assert_eq!(translate("[[:d:]]"), "[[:digit:]]");
        assert_eq!(translate("[[:s:]]"), "[[:space:]]");
        assert_eq!(translate("[[:w:]]"), "[[:word:]]");
        assert_eq!(translate("[^[:space:]]"), "[^[:space:]]");
        assert!(translate_err("[[:^alpha:]]").contains("invalid character class"));
        assert!(translate_err("[[:nope:]]").contains("invalid character class"));
    }

    #[test]
    fn collating_symbols_resolve_through_the_portable_table() {
        assert_eq!(translate("[[.hyphen.]]"), r"[\x2D]");
        assert_eq!(translate("[[.NUL.]x]"), r"[\x00x]");
        assert_eq!(translate("[[.a.]-z]"), "[a-z]");
        assert!(translate_err("[[.-.]]").contains("invalid collating element"));
        assert!(translate_err("[[.ab.]]").contains("invalid collating element"));
    }

    #[test]
    fn equivalence_classes_case_fold() {
        assert_eq!(translate("[[=a=]]"), "[aA]");
        assert_eq!(translate("[[=A=]]"), "[aA]");
        assert_eq!(translate("[[=comma=]]"), r"[\x2C]");
        assert!(translate_err("[[=5=]]").contains("invalid equivalence class"));
        assert!(translate_err("[[=a=]-z]").contains("invalid start of range"));
    }

    #[test]
    fn multi_byte_utf8_members_become_byte_members() {
        // POSIX ERE over bytes: each UTF-8 code unit is its own member.
        assert_eq!(translate("[é]"), r"[\xC3\xA9]");
    }

    #[test]
    fn unterminated_expressions_are_rejected() {
        assert!(translate_err("[a").contains("unterminated"));
        assert!(translate_err("[a-").contains("unterminated"));
        assert!(translate_err("[]").contains("unterminated"));
        assert!(translate_err("[^]").contains("unterminated"));
        assert!(translate_err("[[.hyphen.]").contains("unterminated"));
        assert!(translate_err("[[:alpha").contains("unterminated"));
    }

    #[test]
    fn bracket_end_scanner_matches_the_grammar() {
        assert_eq!(bracket_expression_end(b"[abc]", 0), Some(4));
        assert_eq!(bracket_expression_end(b"[]a]", 0), Some(3));
        assert_eq!(bracket_expression_end(b"[^]a]", 0), Some(4));
        assert_eq!(bracket_expression_end(b"[[:alpha:]]", 0), Some(10));
        assert_eq!(bracket_expression_end(b"[[.].]x]", 0), Some(7));
        assert_eq!(bracket_expression_end(b"[abc", 0), None);
        assert_eq!(bracket_expression_end(b"[[:alpha:]", 0), None);
    }

    #[test]
    fn sign_crossing_ranges_split_into_two_byte_ranges() {
        // Low endpoint 0xA0 (signed -96) to high endpoint '@' (0x40): valid
        // under signed comparison, covering 0x00..=0x40 and 0xA0..=0xFF.
        let pattern = [b'[', 0xA0, b'-', b'@', b']'];
        let translated = translate_posix_ere(&pattern).expect("sign-crossing range translates");
        assert_eq!(
            String::from_utf8(translated).expect("ASCII output"),
            r"[\x00-\x40\xA0-\xFF]"
        );
    }
}
