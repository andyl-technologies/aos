//! Comment-preserving, compare-and-swap mutations for `mkUpstream` literals.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use aos_maintain::plan::SemanticMutation;
use rnix::StrPart;
use rnix::types::{
    Apply, AttrSet, EntryHolder as _, Ident, KeyValue, Str, TokenWrapper as _, TypedNode as _,
};

/// Applies exact semantic mutations to one uniquely identified `mkUpstream` set.
///
/// The returned source preserves every byte outside literal value ranges. No
/// source positions, regular expressions, or first-match fallback are used.
///
/// # Errors
///
/// Returns an error for invalid Nix syntax, dynamic attribute paths, missing
/// or duplicate units/fields, non-literal values, or expected-value mismatch.
pub(super) fn apply(source: &str, unit_id: &str, mutations: &[SemanticMutation]) -> Result<String> {
    let parsed = rnix::parse(source);
    if !parsed.errors().is_empty() {
        bail!("owner file is not valid Nix syntax");
    }
    let candidates = parsed
        .node()
        .descendants()
        .filter_map(Apply::cast)
        .filter(|apply| {
            apply
                .lambda()
                .is_some_and(|lambda| lambda.to_string().trim() == "mkUpstream")
        })
        .filter_map(|apply| apply.value().and_then(AttrSet::cast))
        .filter(|set| {
            collect_fields(set)
                .ok()
                .and_then(|fields| fields.get(&vec!["unitId".to_string()]).cloned())
                .and_then(|values| values.first().cloned())
                .and_then(|value| string_literal(&value))
                .is_some_and(|value| value == unit_id)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        bail!("owner file must contain exactly one matching literal mkUpstream unit");
    }
    let set = candidates
        .first()
        .ok_or_else(|| anyhow::anyhow!("matching mkUpstream unit disappeared"))?;
    let fields = collect_fields(set)?;
    let mut replacements = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        let values = fields
            .get(&mutation.field_path)
            .ok_or_else(|| anyhow::anyhow!("planned semantic field is absent"))?;
        if values.len() != 1 {
            bail!("planned semantic field is not unique");
        }
        let value = values
            .first()
            .ok_or_else(|| anyhow::anyhow!("planned semantic field disappeared"))?;
        let current = string_literal(value)
            .ok_or_else(|| anyhow::anyhow!("planned semantic field is not a literal string"))?;
        if current != mutation.expected {
            bail!("planned semantic field does not match its expected old value");
        }
        let range = value.text_range();
        replacements.push((
            usize::from(range.start()),
            usize::from(range.end()),
            nix_string(&mutation.replacement)?,
        ));
    }
    replacements.sort_by_key(|replacement| replacement.0);
    if replacements.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        bail!("planned semantic mutation ranges overlap");
    }

    let mut output = source.to_string();
    for (start, end, replacement) in replacements.into_iter().rev() {
        output.replace_range(start..end, &replacement);
    }
    let reparsed = rnix::parse(&output);
    if !reparsed.errors().is_empty() {
        bail!("semantic mutation produced invalid Nix syntax");
    }
    Ok(output)
}

fn collect_fields(set: &AttrSet) -> Result<BTreeMap<Vec<String>, Vec<rnix::SyntaxNode>>> {
    let mut output = BTreeMap::new();
    collect_set(set, &[], &mut output)?;
    Ok(output)
}

fn collect_set(
    set: &AttrSet,
    prefix: &[String],
    output: &mut BTreeMap<Vec<String>, Vec<rnix::SyntaxNode>>,
) -> Result<()> {
    for entry in set.entries() {
        let mut path = prefix.to_vec();
        path.extend(key_path(&entry)?);
        let value = entry
            .value()
            .ok_or_else(|| anyhow::anyhow!("Nix attribute lacks a value"))?;
        output.entry(path.clone()).or_default().push(value.clone());
        if let Some(child) = AttrSet::cast(value) {
            collect_set(&child, &path, output)?;
        }
    }
    Ok(())
}

fn key_path(entry: &KeyValue) -> Result<Vec<String>> {
    let key = entry
        .key()
        .ok_or_else(|| anyhow::anyhow!("Nix attribute lacks a key"))?;
    key.path()
        .map(|node| {
            Ident::cast(node)
                .map(|ident| ident.as_str().to_string())
                .ok_or_else(|| anyhow::anyhow!("dynamic Nix attribute path is not editable"))
        })
        .collect()
}

fn string_literal(node: &rnix::SyntaxNode) -> Option<String> {
    let string = Str::cast(node.clone())?;
    match string.parts().as_slice() {
        [StrPart::Literal(value)] => Some(value.to_string()),
        _ => None,
    }
}

fn nix_string(value: &str) -> Result<String> {
    if value.len() > 4096 || value.bytes().any(|byte| byte == 0) {
        bail!("replacement literal is oversized or contains NUL");
    }
    let json = serde_json::to_string(value)?;
    Ok(json.replace("${", "\\${"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(path: &[&str], expected: &str, replacement: &str) -> SemanticMutation {
        SemanticMutation {
            owner: "pkgs/test.nix".to_string(),
            field_path: path.iter().map(|part| (*part).to_string()).collect(),
            expected: expected.to_string(),
            replacement: replacement.to_string(),
        }
    }

    #[test]
    fn edits_only_exact_literals_in_the_selected_unit() -> Result<()> {
        let source = r#"let
  upstream = mkUpstream {
    unitId = "zlib-1";
    package.currentVersion = "1.3.1"; # keep this comment
    components.main.current = {
      upstreamId = "v1.3.1";
      comparisonVersion = "1.3.1";
    };
  };
  unrelated = "1.3.1";
in upstream
"#;
        let updated = apply(
            source,
            "zlib-1",
            &[
                mutation(&["package", "currentVersion"], "1.3.1", "1.3.2"),
                mutation(
                    &["components", "main", "current", "upstreamId"],
                    "v1.3.1",
                    "v1.3.2",
                ),
            ],
        )?;

        assert!(updated.contains("currentVersion = \"1.3.2\"; # keep this comment"));
        assert!(updated.contains("upstreamId = \"v1.3.2\";"));
        assert!(updated.contains("unrelated = \"1.3.1\";"));
        Ok(())
    }

    #[test]
    fn expected_value_mismatch_and_duplicate_units_fail_closed() {
        let source = r#"mkUpstream { unitId = "zlib-1"; package.currentVersion = "1"; }"#;
        assert!(
            apply(
                source,
                "zlib-1",
                &[mutation(&["package", "currentVersion"], "0", "2")]
            )
            .is_err()
        );
        let duplicate = format!("[ ({source}) ({source}) ]");
        assert!(apply(&duplicate, "zlib-1", &[]).is_err());
    }
}
