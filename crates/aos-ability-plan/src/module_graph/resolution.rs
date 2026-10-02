//! Resolves deferred inputs while preserving declared collection semantics.
//!
//! Symbolic reference order need not match the order of returned values. Only
//! collections whose schema declares set semantics are normalized after result
//! substitution; ordinary lists retain their authored execution order.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use aos_ability_model::OptionType;
use aos_contract::canonical;
use serde_json::Value;

use super::validation;

pub(super) fn normalize(value: &mut Value, schema: &OptionType) -> Result<()> {
    match schema {
        OptionType::List {
            element,
            canonical_order,
            ..
        } => normalize_list(value, element, *canonical_order)?,
        OptionType::Set { element } => normalize_list(value, element, true)?,
        OptionType::Submodule { fields, .. } | OptionType::DocumentRecord { fields, .. } => {
            if let Some(values) = value.as_object_mut() {
                for (name, field) in fields {
                    if let Some(value) = values.get_mut(name) {
                        normalize(value, field)?;
                    }
                }
            }
        }
        OptionType::Record { fields, .. } => {
            if let Some(values) = value.as_object_mut() {
                for (name, field) in fields {
                    if let Some(value) = values.get_mut(name.as_str()) {
                        normalize(value, field)?;
                    }
                }
            }
        }
        OptionType::AttrsOf { value: field, .. } | OptionType::Map { value: field, .. } => {
            if let Some(values) = value.as_object_mut() {
                for value in values.values_mut() {
                    normalize(value, field)?;
                }
            }
        }
        OptionType::TaggedUnion { tag, variants } => {
            if let Some(tag) = value.get(tag.as_str()).and_then(Value::as_str) {
                if let Some((_, variant)) = variants.iter().find(|(name, _)| name.as_str() == tag) {
                    normalize(value, variant)?;
                }
            }
        }
        OptionType::Nullable { value: inner } | OptionType::Optional { value: inner } => {
            if !value.is_null() {
                normalize(value, inner)?;
            }
        }
        OptionType::Refined { value: inner, .. } => normalize(value, inner)?,
        OptionType::OneOf { alternatives } => normalize_alternatives(value, alternatives)?,
        OptionType::DisjointUnion { variants } => normalize_alternatives(value, variants)?,
        _ => {}
    }
    Ok(())
}

fn normalize_list(value: &mut Value, element: &OptionType, canonical_set: bool) -> Result<()> {
    let Some(values) = value.as_array_mut() else {
        return Ok(());
    };
    for value in values.iter_mut() {
        normalize(value, element)?;
    }
    if canonical_set {
        let mut distinct = BTreeMap::new();
        for value in std::mem::take(values) {
            distinct.insert(canonical::to_vec(&value)?, value);
        }
        values.extend(distinct.into_values());
    }
    Ok(())
}

fn normalize_alternatives(value: &mut Value, alternatives: &[OptionType]) -> Result<()> {
    let mut selected = None;
    for alternative in alternatives {
        let mut candidate = value.clone();
        if normalize(&mut candidate, alternative).is_err()
            || validation::check_concrete(&candidate, alternative).is_err()
        {
            continue;
        }
        if let Some(previous) = &selected {
            ensure!(
                previous == &candidate,
                "input union has ambiguous collection semantics"
            );
        } else {
            selected = Some(candidate);
        }
    }
    if let Some(selected) = selected {
        *value = selected;
    }
    Ok(())
}
