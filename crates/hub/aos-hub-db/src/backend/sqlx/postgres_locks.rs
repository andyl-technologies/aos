//! Groups consecutive PostgreSQL point locks without changing their order.
//!
//! Each materialized CTE counts its predecessor before locking its own rows.
//! A missing predecessor row prevents later locks, and the caller checks every
//! count before executing mutations. Values remain bound parameters; unsupported
//! SQL shapes retain the ordinary individual-query path.

use anyhow::Result;

use crate::backend::CheckedStatement;
use crate::value::Value;

const MAX_LOCKS: usize = 64;
const MAX_PARAMETERS: usize = 32_768;
const MAX_SQL_BYTES: usize = 512 * 1024;

/// Retains one bounded ordered lock query and its per-lock assertions.
pub(super) struct Compiled {
    pub(super) sql: String,
    pub(super) parameters: Vec<Value>,
    pub(super) expected: Vec<u64>,
}

/// Compiles a consecutive prefix of explicitly grouped unique-key point locks.
///
/// # Errors
/// Returns a translation error from an original PostgreSQL lock query.
pub(super) fn compile(statements: &[CheckedStatement]) -> Result<Option<Compiled>> {
    let mut clauses = Vec::new();
    let mut parameters = Vec::new();
    let mut expected = Vec::new();
    let mut bytes = 0;

    for checked in statements.iter().take(MAX_LOCKS) {
        let (Some(lock), Some(count)) = (&checked.postgres_lock_sql, checked.expected_rows) else {
            break;
        };
        if !lock.groupable_point || count != 1 {
            break;
        }
        if parameters.len() + checked.statement.params.len() > MAX_PARAMETERS {
            break;
        }
        let Some(sql) = rebase(lock.translated_sql()?, parameters.len()) else {
            break;
        };
        let index = expected.len();
        let prerequisite = if index == 0 {
            String::new()
        } else {
            format!(
                " WHERE (SELECT COUNT(*) FROM aos_lock_{}) = {}",
                index - 1,
                expected[index - 1]
            )
        };
        let clause = format!(
            "aos_lock_{index} AS MATERIALIZED (SELECT * FROM ({sql}) aos_locked{prerequisite})"
        );
        // Include the final scalar count and separators in the SQL bound.
        let clause_bytes = clause.len() + 128;
        if bytes + clause_bytes > MAX_SQL_BYTES {
            break;
        }
        bytes += clause_bytes;
        clauses.push(clause);
        parameters.extend_from_slice(&checked.statement.params);
        expected.push(count);
    }

    if expected.len() < 2 {
        return Ok(None);
    }
    let counts = (0..expected.len())
        .map(|index| format!("(SELECT COUNT(*) FROM aos_lock_{index})"))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(Some(Compiled {
        sql: format!("WITH {} SELECT {counts}", clauses.join(", ")),
        parameters,
        expected,
    }))
}

/// Rebases only numbered placeholders outside ordinary quoted SQL tokens.
fn rebase(sql: &str, offset: usize) -> Option<String> {
    let mut output = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '\'' | '"' => {
                let quote = character;
                output.push(quote);
                loop {
                    let character = chars.next()?;
                    // Escape strings and nonstandard quoted forms use the
                    // individual path rather than assuming a server setting.
                    if character == '\\' {
                        return None;
                    }
                    output.push(character);
                    if character == quote {
                        if chars.peek() == Some(&quote) {
                            output.push(chars.next()?);
                        } else {
                            break;
                        }
                    }
                }
            }
            '-' if chars.peek() == Some(&'-') => return None,
            '/' if chars.peek() == Some(&'*') => return None,
            '$' => {
                let mut digits = String::new();
                while chars.peek().is_some_and(char::is_ascii_digit) {
                    digits.push(chars.next()?);
                }
                // Dollar-quoted strings are deliberately left to the ordinary
                // executor. No rewriting is needed for that fallback.
                let index = digits.parse::<usize>().ok()?;
                if index == 0 {
                    return None;
                }
                output.push('$');
                output.push_str(&offset.checked_add(index)?.to_string());
            }
            _ => output.push(character),
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests;
