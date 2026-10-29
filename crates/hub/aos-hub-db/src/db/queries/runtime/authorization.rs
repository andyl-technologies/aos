//! Validates live authorization closures against their independent parent graph.

use super::*;

impl Database {
    /// Loads a stable target scope together with its authoritative ancestor closure.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or if stored scope graph data is
    /// malformed or incomplete. A syntactically invalid or unknown target
    /// returns `Ok(None)` and therefore fails authorization closed.
    pub async fn authorization_context(
        &self,
        scope_key: &str,
    ) -> Result<Option<aos_hub_model::domain::iam::AuthorizationContext>> {
        let Some(target) = aos_hub_model::domain::Scope::try_parse(scope_key) else {
            return Ok(None);
        };
        let rows = self
            .backend
            .query(
                "SELECT c.ancestor_scope_key, c.depth, ancestor.scope_key,
                        ancestor.parent_scope_key, ancestor.org_id
                   FROM authorization_scope_ancestors c
                   JOIN authorization_scopes d ON d.scope_key = c.descendant_scope_key
                   LEFT JOIN orgs o ON o.id = d.org_id
                   LEFT JOIN authorization_scopes ancestor ON ancestor.scope_key = c.ancestor_scope_key
                  WHERE c.descendant_scope_key = ?1
                    AND (d.org_id IS NULL OR o.deleted_at IS NULL)
                  ORDER BY c.depth",
                &vals![scope_key],
            )
            .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let stored = rows
            .iter()
            .map(|row| {
                let raw: String = row.get(0)?;
                let scope = aos_hub_model::domain::Scope::try_parse(&raw)
                    .context("authorization graph contains a non-canonical scope")?;
                Ok((scope, row.get::<i64>(1)?))
            })
            .collect::<Result<Vec<_>>>()?;
        // The closure selects candidate rows; it is never trusted as the parent
        // graph. Reconstruct that graph independently from the joined records,
        // then require the complete ordered closure to match it exactly.
        let parents = rows
            .iter()
            .map(|row| {
                let key = row
                    .get::<Option<String>>(2)?
                    .context("authorization scope parent is missing")?;
                Ok((
                    key,
                    (row.get::<Option<String>>(3)?, row.get::<Option<i64>>(4)?),
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let mut expected = Vec::new();
        let mut cursor = Some(scope_key.to_string());
        let mut expected_org: Option<Option<i64>> = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = cursor {
            if !seen.insert(key.clone()) {
                bail!("authorization scope parent graph contains a cycle");
            }
            let (parent, org_id) = parents
                .get(&key)
                .context("authorization scope parent is missing")?;
            let org_id = *org_id;
            if let Some(Some(child_org)) = expected_org {
                if org_id != Some(child_org) && key != "instance" {
                    bail!("authorization scope parent crosses organization ownership");
                }
            }
            expected_org = Some(org_id);
            let parsed = aos_hub_model::domain::Scope::try_parse(&key)
                .context("authorization scope parent is non-canonical")?;
            expected.push((parsed, i64::try_from(expected.len())?));
            if expected.len() > 8 {
                bail!("authorization scope parent graph exceeds the closed topology depth");
            }
            cursor = parent.clone();
        }
        if stored != expected {
            bail!("authorization ancestor closure does not exactly match the parent graph");
        }
        let ancestors = stored.into_iter().map(|(scope, _)| scope).collect();
        let context = aos_hub_model::domain::iam::AuthorizationContext::try_new(target, ancestors)
            .map_err(anyhow::Error::msg)?;
        Ok(Some(context))
    }
}
