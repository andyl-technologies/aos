//! Held-snapshot checks of admitted compiled CHECK and foreign-key expressions.

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use sqlx::{Postgres, Transaction};

use super::{catalogue::Fact, quote, refresh_timeout};

pub(super) async fn constraints(
    transaction: &mut Transaction<'static, Postgres>,
    facts: &[Fact],
    deadline: Instant,
    timeout: Duration,
) -> Result<usize> {
    let mut checked = 0_usize;
    for fact in facts.iter().filter(|fact| fact.kind == "constraint") {
        let kind = fact.detail["kind"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid admitted constraint"))?;
        if !matches!(kind, "c" | "f") {
            continue;
        }
        ensure!(
            fact.detail["validated"] == true && fact.detail["enforced"] == true,
            "source constraint is not validated and enforced"
        );
        let violation = if kind == "c" {
            let expression = fact.detail["expression"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing check expression"))?;
            // Semantic catalogue admission precedes this query: these exact SQL
            // tokens are authenticated against the compiled PG18 contract.
            format!(
                "SELECT EXISTS (SELECT 1 FROM public.{} WHERE ({expression}) IS FALSE)",
                quote(&fact.owner)
            )
        } else {
            ensure!(
                fact.detail["referenced_schema"] == "public" && fact.detail["match"] == "s",
                "unsupported FK semantics"
            );
            let columns = names(&fact.detail["columns"])?;
            let references = names(&fact.detail["referenced_columns"])?;
            ensure!(
                !columns.is_empty() && columns.len() == references.len(),
                "invalid FK columns"
            );
            let target = fact.detail["referenced_table"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing FK target"))?;
            let nonnull = columns
                .iter()
                .map(|column| format!("child.{} IS NOT NULL", quote(column)))
                .collect::<Vec<_>>()
                .join(" AND ");
            let equality = columns
                .iter()
                .zip(&references)
                .map(|(left, right)| format!("child.{}=parent.{}", quote(left), quote(right)))
                .collect::<Vec<_>>()
                .join(" AND ");
            format!(
                "SELECT EXISTS (SELECT 1 FROM public.{} child WHERE {nonnull} AND NOT EXISTS \
                (SELECT 1 FROM public.{} parent WHERE {equality}))",
                quote(&fact.owner),
                quote(target)
            )
        };
        refresh_timeout(transaction, deadline, timeout).await?;
        let invalid: bool = sqlx::query_scalar(&violation)
            .fetch_one(&mut **transaction)
            .await?;
        ensure!(
            !invalid,
            "source data violates an admitted compiled constraint"
        );
        checked = checked
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("constraint count overflow"))?;
    }
    Ok(checked)
}

fn names(value: &serde_json::Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid constraint columns"))?
        .iter()
        .map(|name| {
            name.as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid constraint name"))
        })
        .collect()
}
