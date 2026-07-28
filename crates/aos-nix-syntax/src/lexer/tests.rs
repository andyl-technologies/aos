//! Behavioral lexer tests pinned against Nix's tokenization.

use super::*;
fn lex_kinds(source: &str) -> Result<Vec<TokenKind>, LexError> {
    Lexer::from_source_str(source)
        .map(|result| result.map(|token| token.kind))
        .collect()
}

fn lex_tokens(source: &str) -> Result<Vec<Token>, LexError> {
    Lexer::from_source_str(source).collect()
}

#[test]
fn token_kind_is_one_byte_and_token_is_copy_sized() {
    assert_eq!(std::mem::size_of::<TokenKind>(), 1);
    assert_eq!(std::mem::size_of::<Span>(), 8);
    assert!(std::mem::size_of::<Token>() <= 12);
}

#[test]
fn emits_keywords_identifiers_and_trivia() {
    let kinds = lex_kinds("let x' = 1; # hi\nin x'").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Let,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Assign,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Semi,
            TokenKind::Whitespace,
            TokenKind::LineComment,
            TokenKind::Whitespace,
            TokenKind::In,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn lexical_identifier_and_number_boundaries_match_pinned_nix() {
    let source = "foo-bar x' _ a0 1 1. .5 1.e10 1.5e-3 3E8 1e10 0x10";
    let tokens = lex_tokens(source).expect("lexes");
    let lexer = Lexer::from_source_str(source);
    let significant = tokens
        .iter()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::Eof)
        .map(|token| {
            (
                token.kind,
                String::from_utf8(lexer.slice(*token).expect("token span is valid").to_vec())
                    .expect("fixture is UTF-8"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        significant,
        vec![
            (TokenKind::Ident, "foo-bar".to_string()),
            (TokenKind::Ident, "x'".to_string()),
            (TokenKind::Ident, "_".to_string()),
            (TokenKind::Ident, "a0".to_string()),
            (TokenKind::Int, "1".to_string()),
            (TokenKind::Float, "1.".to_string()),
            (TokenKind::Float, ".5".to_string()),
            (TokenKind::Float, "1.e10".to_string()),
            (TokenKind::Float, "1.5e-3".to_string()),
            (TokenKind::Int, "3".to_string()),
            (TokenKind::Ident, "E8".to_string()),
            (TokenKind::Int, "1".to_string()),
            (TokenKind::Ident, "e10".to_string()),
            (TokenKind::Int, "0".to_string()),
            (TokenKind::Ident, "x10".to_string()),
        ]
    );
}

#[test]
fn comments_whitespace_and_non_nesting_block_comments_match_pinned_nix() {
    let mut lexer = Lexer::from_source_str("/* a /* b */ c */\r\n\t# line\nx");

    let block = lexer.next_token().expect("block comment token");
    assert_eq!(block.kind, TokenKind::BlockComment);
    assert_eq!(
        lexer.slice(block).expect("valid block span"),
        b"/* a /* b */"
    );

    let space = lexer.next_token().expect("space token");
    assert_eq!(space.kind, TokenKind::Whitespace);
    assert_eq!(lexer.slice(space).expect("valid space span"), b" ");

    let ident = lexer.next_token().expect("identifier token");
    assert_eq!(ident.kind, TokenKind::Ident);
    assert_eq!(lexer.slice(ident).expect("valid ident span"), b"c");

    let mut lexer = Lexer::from_source_str("\r\n\t# line\nx");
    let whitespace = lexer.next_token().expect("whitespace token");
    assert_eq!(whitespace.kind, TokenKind::Whitespace);
    assert_eq!(
        lexer.slice(whitespace).expect("valid whitespace span"),
        b"\r\n\t"
    );
    let line_comment = lexer.next_token().expect("line comment token");
    assert_eq!(line_comment.kind, TokenKind::LineComment);
    assert_eq!(
        lexer.slice(line_comment).expect("valid line comment span"),
        b"# line"
    );

    let mut lexer = Lexer::from_source_str("# cr\rx");
    let line_comment = lexer.next_token().expect("line comment token");
    assert_eq!(line_comment.kind, TokenKind::LineComment);
    assert_eq!(
        lexer.slice(line_comment).expect("valid line comment span"),
        b"# cr"
    );
    let whitespace = lexer.next_token().expect("CR whitespace token");
    assert_eq!(whitespace.kind, TokenKind::Whitespace);
    assert_eq!(
        lexer.slice(whitespace).expect("valid whitespace span"),
        b"\r"
    );
    let ident = lexer.next_token().expect("identifier after CR");
    assert_eq!(ident.kind, TokenKind::Ident);
    assert_eq!(lexer.slice(ident).expect("valid ident span"), b"x");
}

#[test]
fn keeps_source_slices_by_span() {
    let mut lexer = Lexer::from_source_str("abc 123");
    let ident = lexer.next_token().expect("identifier token");
    let trivia = lexer.next_token().expect("trivia token");
    let int = lexer.next_token().expect("integer token");

    assert_eq!(lexer.slice(ident).expect("valid ident span"), b"abc");
    assert_eq!(lexer.slice(trivia).expect("valid trivia span"), b" ");
    assert_eq!(lexer.slice(int).expect("valid integer span"), b"123");
}

#[test]
fn retains_comment_trivia_spans_for_diagnostics() {
    let mut lexer = Lexer::from_source_str("x # keep me\n y");
    let ident = lexer.next_token().expect("identifier token");
    let space = lexer.next_token().expect("space token");
    let comment = lexer.next_token().expect("comment token");
    let trailing = lexer.next_token().expect("trailing whitespace token");

    assert_eq!(lexer.slice(ident).expect("valid ident span"), b"x");
    assert_eq!(lexer.slice(space).expect("valid space span"), b" ");
    assert_eq!(
        lexer.slice(comment).expect("valid comment span"),
        b"# keep me"
    );
    assert_eq!(lexer.slice(trailing).expect("valid trailing span"), b"\n ");
}

#[test]
fn supports_one_token_lookahead() {
    let mut lexer = Lexer::from_source_str("let");
    let peeked = lexer.peek().expect("peek token");
    let next = lexer.next_token().expect("next token");
    assert_eq!(peeked, next);
    assert_eq!(next.kind, TokenKind::Let);
}

#[test]
fn classifies_local_nix_number_boundaries() {
    let kinds = lex_kinds("1 1. .5 1e10 1.5e-3").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Float,
            TokenKind::Whitespace,
            TokenKind::Float,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Float,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn distinguishes_paths_division_update_and_uris() {
    let kinds = lex_kinds("a/b a /b a / b ./x ../y /abs ~/z a // b https://x/y").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Slash,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Update,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Uri,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn accepts_cxx_nix_path_prefix_boundaries() {
    let kinds = lex_kinds("foo.bar/baz foo+bar/baz 1/foo 1.5/foo foo/bar/").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn slash_whitespace_disambiguates_division_from_paths() {
    let kinds = lex_kinds("1/2 1/ 2 1 /2 1 / 2 a/2 a/ 2").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Slash,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Slash,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Slash,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Eof,
        ]
    );

    let kinds = lex_kinds("1/*x*/ / 2 1/**//2").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Int,
            TokenKind::BlockComment,
            TokenKind::Whitespace,
            TokenKind::Slash,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::Whitespace,
            TokenKind::Int,
            TokenKind::BlockComment,
            TokenKind::Path,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn dot_slash_dot_is_path_but_dot_slash_is_not() {
    let kinds = lex_kinds("./. ./").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Dot,
            TokenKind::Slash,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn home_slash_path_requires_segment_or_interpolation() {
    let kinds = lex_kinds("~/foo ~/. ~/${x}").expect("home paths lex");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::Whitespace,
            TokenKind::Path,
            TokenKind::DollarBrace,
            TokenKind::Ident,
            TokenKind::RBrace,
            TokenKind::Eof,
        ]
    );

    assert_eq!(
        lex_kinds("~/")
            .expect_err("bare home slash path is invalid")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'~')
    );
}

#[test]
fn rejects_or_splits_invalid_path_body_bytes() {
    assert_eq!(
        lex_kinds("foo$bar/baz")
            .expect_err("dollar is not a path body byte")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'$')
    );
    assert_eq!(
        lex_kinds("foo%bar/baz")
            .expect_err("percent is not a path body byte")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'%')
    );

    let kinds = lex_kinds("foo*bar/baz").expect("star splits the expression");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Ident,
            TokenKind::Star,
            TokenKind::Path,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn accepts_and_rejects_uri_scheme_boundaries() {
    let kinds = lex_kinds("git+ssh://example/path foo.bar:baz foo-bar:baz").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Uri,
            TokenKind::Whitespace,
            TokenKind::Uri,
            TokenKind::Whitespace,
            TokenKind::Uri,
            TokenKind::Eof,
        ]
    );

    let kinds = lex_kinds("foo_bar:baz foo'bar:baz").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Ident,
            TokenKind::Colon,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Colon,
            TokenKind::Ident,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn uri_fragment_marker_starts_line_comment() {
    let kinds =
        lex_kinds("https://example.test/%23 https://example.test/path#fragment").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Uri,
            TokenKind::Whitespace,
            TokenKind::Uri,
            TokenKind::LineComment,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn splits_path_interpolation_into_expression_tokens() {
    let kinds = lex_kinds("./a/${x}/b").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::Path,
            TokenKind::DollarBrace,
            TokenKind::Ident,
            TokenKind::RBrace,
            TokenKind::Path,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn distinguishes_search_paths_from_comparison() {
    let kinds = lex_kinds("<nixpkgs/lib> a < b <= c <| d").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::SPath,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Less,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::LessEq,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::PipeLeft,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn validates_search_path_segments() {
    let kinds = lex_kinds("<a/b/c>").expect("multi-segment search path lexes");
    assert_eq!(kinds, vec![TokenKind::SPath, TokenKind::Eof]);

    let leading_slash = lex_kinds("</foo>").expect("leading slash is not an SPath token");
    assert_eq!(
        leading_slash,
        vec![
            TokenKind::Less,
            TokenKind::Path,
            TokenKind::Greater,
            TokenKind::Eof,
        ]
    );

    assert_eq!(
        lex_kinds("<foo/>")
            .expect_err("trailing slash is invalid in search path")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'>')
    );
    assert_eq!(
        lex_kinds("<foo//bar>")
            .expect_err("empty search path segment is invalid")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'/')
    );
}

#[test]
fn rejects_invalid_search_path_body_bytes() {
    assert_eq!(
        lex_kinds("<foo$bar>")
            .expect_err("dollar is invalid in search path")
            .kind(),
        &LexErrorKind::UnexpectedByte(b'$')
    );
    assert_eq!(
        lex_kinds("<foo:bar>")
            .expect_err("colon is invalid in search path")
            .kind(),
        &LexErrorKind::UnexpectedByte(b':')
    );
}

#[test]
fn emits_double_quoted_string_fragments_and_interpolation() {
    let kinds = lex_kinds("\"a${x}b\"").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::StrStart,
            TokenKind::StrPart,
            TokenKind::DollarBrace,
            TokenKind::Ident,
            TokenKind::RBrace,
            TokenKind::StrPart,
            TokenKind::StrEnd,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn keeps_escaped_double_string_interpolation_as_text() {
    let tokens = lex_tokens("\"\\${x} $${y}\"").expect("lexes");
    let parts: Vec<&[u8]> = tokens
        .iter()
        .filter(|token| token.kind == TokenKind::StrPart)
        .map(|token| {
            Lexer::from_source_str("\"\\${x} $${y}\"")
                .slice(*token)
                .expect("valid string span")
        })
        .collect();

    assert_eq!(parts, vec![b"\\${x} $${y}".as_slice()]);
}

#[test]
fn tracks_nested_interpolation_braces() {
    let kinds = lex_kinds("\"${{ a = \"b\"; }}\"").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::StrStart,
            TokenKind::DollarBrace,
            TokenKind::LBrace,
            TokenKind::Whitespace,
            TokenKind::Ident,
            TokenKind::Whitespace,
            TokenKind::Assign,
            TokenKind::Whitespace,
            TokenKind::StrStart,
            TokenKind::StrPart,
            TokenKind::StrEnd,
            TokenKind::Semi,
            TokenKind::Whitespace,
            TokenKind::RBrace,
            TokenKind::RBrace,
            TokenKind::StrEnd,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn emits_indented_string_fragments_and_interpolation() {
    let kinds = lex_kinds("''a${x}b''").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::IndStrStart,
            TokenKind::IndStrPart,
            TokenKind::DollarBrace,
            TokenKind::Ident,
            TokenKind::RBrace,
            TokenKind::IndStrPart,
            TokenKind::IndStrEnd,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn indented_string_escape_prefix_does_not_close() {
    let kinds = lex_kinds("'''''''").expect("lexes");
    assert_eq!(
        kinds,
        vec![
            TokenKind::IndStrStart,
            TokenKind::IndStrPart,
            TokenKind::IndStrEnd,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn keeps_backslash_escaped_indented_string_interpolation_as_text() {
    let source = r"''''\${PORT}''";
    let tokens = lex_tokens(source).expect("lexes");
    let significant = tokens
        .iter()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::Eof)
        .collect::<Vec<_>>();

    assert_eq!(
        significant
            .iter()
            .map(|token| token.kind)
            .collect::<Vec<_>>(),
        vec![
            TokenKind::IndStrStart,
            TokenKind::IndStrPart,
            TokenKind::IndStrEnd,
        ]
    );
    assert_eq!(
        Lexer::from_source_str(source)
            .slice(*significant[1])
            .expect("valid indented string span"),
        br#"''\${PORT}"#
    );
}

#[test]
fn reports_unterminated_constructs() {
    assert_eq!(
        Lexer::from_source_str("/* nope")
            .next_token()
            .expect_err("unterminated block comment")
            .kind(),
        &LexErrorKind::UnterminatedBlockComment
    );
    assert_eq!(
        Lexer::from_source_str("\"nope")
            .nth(2)
            .expect("unterminated string result")
            .expect_err("unterminated string")
            .kind(),
        &LexErrorKind::UnterminatedString
    );
    assert_eq!(
        Lexer::from_source_str("\"${x")
            .last()
            .expect("last token")
            .expect_err("unterminated interpolation")
            .kind(),
        &LexErrorKind::UnterminatedInterpolation
    );
}
