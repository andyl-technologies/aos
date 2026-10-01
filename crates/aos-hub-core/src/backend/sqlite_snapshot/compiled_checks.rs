//! Bounded CHECK extraction from the trusted, SQLite-compiled table catalogue.
//!
//! SQLite discards CHECK expression trees when it reloads a read-only schema.
//! A source integrity PRAGMA consequently does not verify those constraints.
//! This helper preserves expressions from the independently compiled production
//! catalogue for separate evaluation in the pinned source read. It accepts no
//! source SQL and performs no SQL or filesystem operations.
//!
//! This is a lexical extractor, not a general SQL parser. Its input must already
//! have passed SQLite compilation. It admits a single `CREATE TABLE name (...)`
//! declaration, with an optional trailing semicolon. CHECK declarations must
//! occur directly in its table body; unsupported envelopes fail closed.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{ensure, Result};

use super::{
    SchemaObject, MAX_IDENTIFIER_BYTES, MAX_SCHEMA_BYTES, MAX_SCHEMA_OBJECTS, MAX_SCHEMA_SQL_BYTES,
};

const MAX_CHECKS_PER_TABLE: usize = 128;
const MAX_CHECKS: usize = 4096;
const MAX_CHECK_BYTES: usize = 16 * 1024;
const MAX_PARENTHESES: usize = 128;

/// Extracts all CHECK expressions from a bounded trusted compiled catalogue.
///
/// Returned table names are independently compiled identifiers. Expressions
/// retain exact SQL bytes, including literals, identifiers and comments. The
/// caller must place each expression inside `NOT(\nexpression\n)` so CHECK's
/// NULL-pass semantics and trailing line comments are preserved.
///
/// # Errors
///
/// Rejects excessive catalogue/expression sizes, duplicate table names, absent
/// table DDL, malformed protected tokens or unsupported CREATE/CHECK envelopes.
/// Errors contain no input SQL or identifiers.
pub(super) fn extract_compiled_checks(
    objects: &[SchemaObject],
) -> Result<BTreeMap<String, Vec<String>>> {
    ensure!(
        objects.len() <= MAX_SCHEMA_OBJECTS as usize,
        "snapshot compiled checks catalogue exceeds limits"
    );
    let mut bytes = 0usize;
    for object in objects {
        let sql_bytes = object.sql.as_ref().map_or(0, String::len);
        ensure!(
            object.name.len() <= MAX_IDENTIFIER_BYTES as usize
                && object.table.len() <= MAX_IDENTIFIER_BYTES as usize
                && sql_bytes <= MAX_SCHEMA_SQL_BYTES as usize,
            "snapshot compiled checks catalogue exceeds limits"
        );
        bytes = bytes
            .checked_add(object.name.len())
            .and_then(|bytes| bytes.checked_add(object.table.len()))
            .and_then(|bytes| bytes.checked_add(sql_bytes))
            .ok_or_else(|| anyhow::anyhow!("snapshot compiled checks catalogue exceeds limits"))?;
        ensure!(
            bytes <= MAX_SCHEMA_BYTES as usize,
            "snapshot compiled checks catalogue exceeds limits"
        );
    }

    let mut tables = BTreeSet::new();
    let mut checks = BTreeMap::new();
    let mut count = 0usize;
    for object in objects.iter().filter(|object| object.kind == "table") {
        ensure!(
            !object.name.is_empty()
                && object.name == object.table
                && tables.insert(object.name.as_str()),
            "snapshot compiled checks table identity differs"
        );
        let sql = object
            .sql
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("snapshot compiled checks table DDL is absent"))?;
        let expressions =
            extract_table_checks_with_limit(sql, MAX_CHECKS_PER_TABLE.min(MAX_CHECKS - count))?;
        count = count
            .checked_add(expressions.len())
            .ok_or_else(|| anyhow::anyhow!("snapshot compiled checks count exceeds limits"))?;
        ensure!(
            count <= MAX_CHECKS,
            "snapshot compiled checks count exceeds limits"
        );
        if !expressions.is_empty() {
            checks.insert(object.name.clone(), expressions);
        }
    }
    Ok(checks)
}

#[cfg(test)]
fn extract_table_checks(sql: &str) -> Result<Vec<String>> {
    extract_table_checks_with_limit(sql, MAX_CHECKS_PER_TABLE)
}

fn extract_table_checks_with_limit(sql: &str, max_checks: usize) -> Result<Vec<String>> {
    ensure!(
        sql.len() <= MAX_SCHEMA_SQL_BYTES as usize,
        "snapshot compiled checks DDL exceeds limits"
    );
    let mut lexer = Lexer { sql, offset: 0 };
    ensure!(
        lexer.word("CREATE")? && lexer.word("TABLE")?,
        "snapshot compiled checks CREATE envelope is unsupported"
    );
    let name = lexer.next()?;
    ensure!(
        matches!(name, Some(Token::Word(_) | Token::Identifier)),
        "snapshot compiled checks table identifier is invalid"
    );
    ensure!(
        matches!(lexer.next()?, Some(Token::Open)),
        "snapshot compiled checks table body is invalid"
    );

    let mut expressions = Vec::new();
    let mut depth = 1usize;
    while depth != 0 {
        match lexer.next()? {
            Some(Token::Word(range)) if sql[range.clone()].eq_ignore_ascii_case("CHECK") => {
                ensure!(
                    depth == 1 && expressions.len() < max_checks,
                    "snapshot compiled checks declaration exceeds supported bounds"
                );
                ensure!(
                    matches!(lexer.next()?, Some(Token::Open)),
                    "snapshot compiled checks declaration is invalid"
                );
                let start = lexer.offset;
                let mut check_depth = 1usize;
                while check_depth != 0 {
                    match lexer.next()? {
                        Some(Token::Open) => {
                            check_depth += 1;
                            ensure!(
                                check_depth <= MAX_PARENTHESES,
                                "snapshot compiled checks nesting exceeds limits"
                            );
                        }
                        Some(Token::Close) => check_depth -= 1,
                        Some(Token::Other(b';')) | None => {
                            anyhow::bail!("snapshot compiled checks expression is invalid")
                        }
                        _ => {}
                    }
                }
                let end = lexer.offset - 1;
                ensure!(
                    end - start <= MAX_CHECK_BYTES && !sql[start..end].trim().is_empty(),
                    "snapshot compiled checks expression exceeds supported bounds"
                );
                expressions.push(sql[start..end].to_owned());
            }
            Some(Token::Open) => {
                depth += 1;
                ensure!(
                    depth <= MAX_PARENTHESES,
                    "snapshot compiled checks nesting exceeds limits"
                );
            }
            Some(Token::Close) => depth -= 1,
            Some(Token::Other(b';')) | None => {
                anyhow::bail!("snapshot compiled checks table body is invalid")
            }
            _ => {}
        }
    }
    match lexer.next()? {
        None => {}
        Some(Token::Other(b';')) => ensure!(
            lexer.next()?.is_none(),
            "snapshot compiled checks trailing SQL is unsupported"
        ),
        _ => anyhow::bail!("snapshot compiled checks trailing SQL is unsupported"),
    }
    Ok(expressions)
}

enum Token {
    Word(Range<usize>),
    Identifier,
    String,
    Open,
    Close,
    Other(u8),
}

struct Lexer<'a> {
    sql: &'a str,
    offset: usize,
}

impl Lexer<'_> {
    fn word(&mut self, expected: &str) -> Result<bool> {
        Ok(
            matches!(self.next()?, Some(Token::Word(range)) if self.sql[range.clone()].eq_ignore_ascii_case(expected)),
        )
    }

    fn next(&mut self) -> Result<Option<Token>> {
        let bytes = self.sql.as_bytes();
        loop {
            while bytes.get(self.offset).is_some_and(u8::is_ascii_whitespace) {
                self.offset += 1;
            }
            let Some(&byte) = bytes.get(self.offset) else {
                return Ok(None);
            };
            match (byte, bytes.get(self.offset + 1).copied()) {
                (b'-', Some(b'-')) => {
                    self.offset += 2;
                    while bytes.get(self.offset).is_some_and(|byte| *byte != b'\n') {
                        self.offset += 1;
                    }
                }
                (b'/', Some(b'*')) => {
                    self.offset += 2;
                    while self.offset + 1 < bytes.len()
                        && bytes[self.offset..self.offset + 2] != *b"*/"
                    {
                        self.offset += 1;
                    }
                    ensure!(
                        self.offset + 1 < bytes.len(),
                        "snapshot compiled checks comment is unterminated"
                    );
                    self.offset += 2;
                }
                _ => break,
            }
        }

        let byte = bytes[self.offset];
        self.offset += 1;
        Ok(Some(match byte {
            b'(' => Token::Open,
            b')' => Token::Close,
            b'\'' | b'"' | b'`' | b'[' => {
                let close = if byte == b'[' { b']' } else { byte };
                loop {
                    let Some(&next) = bytes.get(self.offset) else {
                        anyhow::bail!("snapshot compiled checks quoted token is unterminated")
                    };
                    self.offset += 1;
                    if next == close {
                        // SQLite single/double/backtick quotes double their
                        // closing delimiter. Bracket identifiers close once.
                        if byte != b'[' && bytes.get(self.offset) == Some(&close) {
                            self.offset += 1;
                        } else {
                            break;
                        }
                    }
                }
                if byte == b'\'' {
                    Token::String
                } else {
                    Token::Identifier
                }
            }
            byte if identifier_byte(byte) => {
                let start = self.offset - 1;
                while bytes
                    .get(self.offset)
                    .is_some_and(|byte| identifier_byte(*byte))
                {
                    self.offset += 1;
                }
                Token::Word(start..self.offset)
            }
            byte => Token::Other(byte),
        }))
    }
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || !byte.is_ascii()
}

#[cfg(test)]
#[path = "compiled_checks/tests.rs"]
mod tests;
