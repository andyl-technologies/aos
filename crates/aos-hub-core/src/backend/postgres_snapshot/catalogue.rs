//! Bounded PostgreSQL 18 semantic catalogue admission.
//!
//! Facts contain logical names, types and constraints, never role/database names,
//! object identifiers or physical constraint/index names. Expression whitespace
//! outside SQL quotes is normalized; literal and operator tokens remain exact.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

const QUERY: &str = include_str!("catalogue.sql");
const MAX_FACTS: i64 = 16_384;
const MAX_FACT_BYTES: i64 = 128 * 1024;
const MAX_TOTAL_BYTES: i64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub kind: String,
    pub owner: String,
    pub detail: Value,
}

pub(super) async fn read(transaction: &mut Transaction<'static, Postgres>) -> Result<Vec<Fact>> {
    // Aggregate lengths on the server before any variable-size catalogue values
    // enter the client. The reader's statement deadline also bounds this audit.
    let budget_sql = format!(
        "SELECT count(*)::bigint, COALESCE(sum(octet_length(detail)), 0)::bigint, \
         COALESCE(max(octet_length(detail)), 0)::bigint FROM ({QUERY}) facts"
    );
    let budget = sqlx::query(&budget_sql)
        .fetch_one(&mut **transaction)
        .await?;
    let count: i64 = budget.try_get(0)?;
    let bytes: i64 = budget.try_get(1)?;
    let largest: i64 = budget.try_get(2)?;
    ensure!(
        (1..=MAX_FACTS).contains(&count) && bytes <= MAX_TOTAL_BYTES && largest <= MAX_FACT_BYTES,
        "PostgreSQL snapshot catalogue exceeds its bounds"
    );

    let rows = sqlx::query(QUERY).fetch_all(&mut **transaction).await?;
    ensure!(
        rows.len() == usize::try_from(count)?,
        "snapshot catalogue count changed"
    );
    let mut facts = Vec::with_capacity(rows.len());
    for row in rows {
        facts.push(Fact {
            kind: row.try_get(0)?,
            owner: row.try_get(1)?,
            detail: serde_json::from_str(&row.try_get::<String, _>(2)?)?,
        });
    }
    Ok(facts)
}

pub(super) fn expected_sha256() -> &'static str {
    include_str!("current8.sha256").trim()
}

pub(super) fn digest(facts: &[Fact]) -> Result<String> {
    let mut normalized = facts.to_vec();
    normalize(&mut normalized)?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(
        &normalized,
    )?)))
}

fn normalize(facts: &mut [Fact]) -> Result<()> {
    for fact in facts.iter_mut() {
        // Object order is not a semantic fact, including when another caller
        // enables serde_json's preserve_order feature in the same build.
        fact.detail.sort_all_objects();
        let detail = fact
            .detail
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid catalogue fact"))?;
        for field in ["expression", "predicate", "default", "definition"] {
            if let Some(Value::String(expression)) = detail.get_mut(field) {
                *expression = expression_tokens(expression)?;
            }
        }
        if let Some(Value::Array(keys)) = detail.get_mut("keys") {
            for key in keys {
                let expression = key
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid index key"))?;
                *key = Value::String(expression_tokens(expression)?);
            }
        }
    }
    facts.sort_by_cached_key(|fact| {
        (
            fact.kind.clone(),
            fact.owner.clone(),
            fact.detail.to_string(),
        )
    });
    Ok(())
}

/// Removes only nonsemantic whitespace, preserving quoted identifiers/literals.
fn expression_tokens(input: &str) -> Result<String> {
    let mut tokens = Vec::new();
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character.is_whitespace() {
            continue;
        }
        let mut token = String::from(character);
        if matches!(character, '\'' | '"') {
            let quote = character;
            let mut closed = false;
            while let Some(next) = characters.next() {
                token.push(next);
                if next == quote {
                    if characters.peek() == Some(&quote) {
                        token.push(
                            characters
                                .next()
                                .ok_or_else(|| anyhow::anyhow!("invalid quote"))?,
                        );
                    } else {
                        closed = true;
                        break;
                    }
                }
            }
            ensure!(closed, "unsupported catalogue expression quoting");
        } else if character.is_alphanumeric() || character == '_' {
            while characters
                .peek()
                .is_some_and(|next| next.is_alphanumeric() || *next == '_')
            {
                token.push(
                    characters
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("invalid token"))?,
                );
            }
        } else if "+-*/<>=~!@#%^&|?:".contains(character) {
            while characters
                .peek()
                .is_some_and(|next| "+-*/<>=~!@#%^&|?:".contains(*next))
            {
                token.push(
                    characters
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("invalid operator"))?,
                );
            }
        }
        tokens.push(token);
    }
    Ok(tokens.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_normalization_preserves_tokens_and_quoted_bytes() {
        assert_eq!(
            expression_tokens("length ( value ) >= 1").unwrap(),
            expression_tokens("length(value)>=1").unwrap()
        );
        assert_ne!(
            expression_tokens("a b").unwrap(),
            expression_tokens("ab").unwrap()
        );
        assert_ne!(
            expression_tokens("x > = 1").unwrap(),
            expression_tokens("x >= 1").unwrap()
        );
        assert_ne!(
            expression_tokens("x='a b'").unwrap(),
            expression_tokens("x='ab'").unwrap()
        );
        assert_eq!(
            expression_tokens("x = 'one'' two'").unwrap(),
            "x = 'one'' two'"
        );
        assert!(expression_tokens("x='unterminated").is_err());
    }
}
