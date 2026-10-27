//! Checks required inline values only on actual changed regular-file entries.
//!
//! Side records retain their independent producer checks and cannot supply an
//! omitted inline index value. Untouched entries remain backfill gaps.

use terrane_format::derived::{AttributeName, AttributeValue};
use terrane_format::indexing::{IndexEvaluationRecipe, IndexKey};
use terrane_format::properties::{EffectiveProperties, PropertyName, Value};
use terrane_format::tree_format::{ContentRef, Entry, EntryKind};

use crate::guard::attributes::RequirementEvidence;
use crate::guard::invalid;
use crate::store::{StoreErrorKind, StoreFailure};

/// Checks applicable requirements without reading content or inferring absence.
///
/// # Errors
/// Rejects unregistered requirements, malformed inline values and applicable
/// changed files without inline values; preserves the exact producing input.
pub(super) fn validate(
    changes: &[(&Entry<'_>, &EffectiveProperties<'_>)],
    producers: &[RequirementEvidence],
) -> Result<(), StoreFailure> {
    for (entry, policy) in changes {
        let Some(Value::Names(names)) = policy.get(PropertyName::Index) else {
            return Err(invalid());
        };
        let mut entries = vec![*entry];
        while let Some(entry) = entries.pop() {
            match &entry.kind {
                EntryKind::Conflict { candidates, base } => {
                    entries.extend(candidates);
                    if let Some(Some(base)) = base {
                        entries.push(base);
                    }
                }
                EntryKind::File { content, .. } => {
                    let object = match content {
                        ContentRef::Inline(object) | ContentRef::Manifest(object) => *object,
                    };
                    for name in names {
                        IndexEvaluationRecipe::new([0; 32], name).map_err(|error| {
                            StoreFailure::with_source(invalid().kind().clone(), error)
                        })?;
                        let inline = entry.attrs.iter().find(|attribute| attribute.name == *name);
                        if let Some(inline) = inline {
                            IndexKey::new(inline.value, object).map_err(|error| {
                                StoreFailure::with_source(invalid().kind().clone(), error)
                            })?;
                            if let Ok(registered) = AttributeName::parse(name) {
                                AttributeValue::decode(registered, inline.value).map_err(
                                    |error| {
                                        StoreFailure::with_source(invalid().kind().clone(), error)
                                    },
                                )?;
                            }
                        } else if !nonapplicable(entry, object, name, producers)? {
                            return Err(StoreFailure::with_source(
                                StoreErrorKind::Unsupported,
                                MissingInline {
                                    object,
                                    attribute: (*name).to_owned(),
                                },
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn nonapplicable(
    entry: &Entry<'_>,
    object: terrane_format::identity::Digest,
    name: &str,
    producers: &[RequirementEvidence],
) -> Result<bool, StoreFailure> {
    let target = match name {
        "class.elf" => "elf",
        "class.shebang" => "shebang",
        _ => return Ok(false),
    };
    let Some(inline) = entry
        .attrs
        .iter()
        .find(|attribute| attribute.name == "class.magic")
    else {
        return Ok(false);
    };
    let magic = AttributeValue::decode(AttributeName::Magic, inline.value)
        .map_err(|error| StoreFailure::with_source(invalid().kind().clone(), error))?;
    let AttributeValue::Magic(magic) = magic else {
        return Err(invalid());
    };
    // Only an actually checked producing witness can exclude conditional coverage.
    Ok(magic.as_str() != target
        && producers.iter().any(|evidence| {
            evidence.attribute.object() == &object
                && evidence.attribute.name() == AttributeName::Magic
                && evidence.attribute.value() == inline.value
        }))
}

/// Identifies the incomplete actual file input without replacing its producer.
#[derive(Debug)]
pub(in crate::guard) struct MissingInline {
    /// Actual changed file identity whose applicable inline value is absent.
    pub(in crate::guard) object: terrane_format::identity::Digest,
    /// Independently resolved required registered inline name.
    pub(in crate::guard) attribute: String,
}

impl std::fmt::Display for MissingInline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "required inline index value {} is absent for {:?}",
            self.attribute, self.object
        )
    }
}

impl std::error::Error for MissingInline {}
