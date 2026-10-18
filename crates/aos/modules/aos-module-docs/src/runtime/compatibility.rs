//! Conservative structural checks for package and OS release interfaces.
//!
//! The check reads generated declarations, never handler programs or defaults.
//! It reports changes requiring a release outside the previous compatibility range
//! or an exact, explained exception.
//! Passing this check does not establish behavioral compatibility.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{ModuleReference, NativeOption, OperationReference, RuntimeDocument, invalid};
use crate::{OptionType, Result, Visibility};

/// Selects the existing release that owns the checked interface.
#[derive(Clone, Debug)]
pub enum ReleaseOwner {
    /// Checks public declarations supplied by this package.
    Package(String),
    /// Checks base declarations versioned by the OS release.
    Os,
}

/// Acknowledges one exact diagnostic with a review explanation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityException {
    /// Identifies the diagnostic and its exact before/after interface snapshots.
    pub id: String,
    /// Explains why the change is acceptable for this release.
    pub reason: String,
}

/// Describes a structural change that cannot silently claim compatibility.
#[derive(Clone, Debug, Serialize)]
pub struct CompatibilityChange {
    /// Binds the diagnostic to the compared releases and structural snapshots.
    pub id: String,
    /// Locates the changed option or operation field.
    pub path: Vec<String>,
    /// Explains the compatibility concern.
    pub reason: String,
    /// Records a matching explicit exception, independently of the compatibility boundary.
    pub waived: bool,
}

/// Reports release policy and the complete set of structural diagnostics.
#[derive(Clone, Debug, Serialize)]
pub struct CompatibilityReport {
    /// Indicates that every diagnostic is acknowledged by release policy or exception.
    pub compatible: bool,
    /// Indicates that the next release falls outside the previous compatibility range.
    pub compatibility_boundary: bool,
    /// Lists structural concerns, including acknowledged changes.
    pub changes: Vec<CompatibilityChange>,
}

struct Surface<'a> {
    name: String,
    version: semver::Version,
    version_requirement: semver::VersionReq,
    options: BTreeMap<Vec<String>, &'a NativeOption>,
    operations: BTreeMap<(String, String), &'a OperationReference>,
}

impl ReleaseOwner {
    fn surface<'a>(&self, document: &'a ModuleReference) -> Result<Surface<'a>> {
        let (name, version, requirement, owner) = match self {
            Self::Package(name) => {
                let mut packages = document
                    .packages
                    .iter()
                    .filter(|package| &package.name == name);
                let package = packages.next().ok_or_else(|| {
                    invalid(format!("interface owner package '{name}' is absent"))
                })?;
                if packages.next().is_some() {
                    return Err(invalid("interface owner has duplicate package identities"));
                }
                (
                    name.clone(),
                    package.version.as_str(),
                    package.version_requirement.as_deref(),
                    name.as_str(),
                )
            }
            Self::Os => {
                let release = document
                    .os_release
                    .as_ref()
                    .ok_or_else(|| invalid("OS interface check requires osRelease metadata"))?;
                (
                    release.name.clone(),
                    release.version.as_str(),
                    None,
                    "@base",
                )
            }
        };
        let version = semver::Version::parse(version).map_err(invalid)?;
        // The previous release's policy belongs to its existing consumers. The
        // next release cannot relax that policy by changing its own declaration.
        let inferred_requirement = format!("^{version}");
        let version_requirement =
            semver::VersionReq::parse(requirement.unwrap_or(&inferred_requirement))
                .map_err(invalid)?;
        let mut options = BTreeMap::new();
        for option in document
            .options
            .iter()
            .filter(|option| option.owner == owner && option.visibility == Visibility::Public)
        {
            if options.insert(option.path.clone(), option).is_some() {
                return Err(invalid("interface owner repeats a public option path"));
            }
        }
        let operations = document
            .abilities
            .iter()
            .flat_map(|(ability, operations)| {
                operations.iter().filter_map(move |(name, operation)| {
                    operation
                        .sources
                        .input
                        .iter()
                        .chain(&operation.sources.result)
                        .any(|source| source.owner == owner)
                        .then_some(((ability.clone(), name.clone()), operation))
                })
            })
            .collect();
        Ok(Surface {
            name,
            version,
            version_requirement,
            options,
            operations,
        })
    }
}

impl Surface<'_> {
    // The snapshot excludes prose, source paths, handler choices, and configured effects.
    fn snapshot(&self) -> Value {
        json!({
            "name": self.name,
            "version": self.version.to_string(),
            "versionRequirement": self.version_requirement.to_string(),
            "options": self.options.values().map(|option| json!({
                "path":option.path, "type":option.option_type,
                "default":option.has_default, "readOnly":option.read_only,
                "extensible":option.extensible
            })).collect::<Vec<_>>(),
            "operations": self.operations.iter().map(|((ability,name), operation)| {
                let defaults:BTreeSet<_> = operation.input_defaults.iter().collect();
                json!({"ability":ability,"operation":name,"input":operation.input_type,
                    "result":operation.result_type,"defaults":defaults})
            }).collect::<Vec<_>>()
        })
    }
}

/// Checks the public structural interface owned by an OS or package release.
///
/// Unchanged types, new operations, and input additions with defaults are accepted.
/// Other type changes are conservatively reported, including changed refinements.
/// Closed result records reject additions because earlier consumers may reject them.
/// A release outside the previous version requirement acknowledges diagnostics
/// but does not erase them from the report. OS releases use the caret range
/// derived from their previous semantic version.
///
/// # Errors
/// Returns an error for non-reference documents, missing or mismatched release
/// owners/platforms, invalid or decreasing release versions, or empty, duplicate,
/// stale, or excessive exceptions. Opaque semantics and handler behavior remain
/// outside this structural check.
pub fn check_compatibility(
    before: &RuntimeDocument,
    after: &RuntimeDocument,
    owner: &ReleaseOwner,
    exceptions: &[CompatibilityException],
) -> Result<CompatibilityReport> {
    let before = before
        .reference()
        .ok_or_else(|| invalid("compatibility requires module reference documents"))?;
    let after = after
        .reference()
        .ok_or_else(|| invalid("compatibility requires module reference documents"))?;
    if before.system != after.system {
        return Err(invalid(
            "interface comparison requires the same target platform",
        ));
    }
    let before = owner.surface(before)?;
    let after = owner.surface(after)?;
    if before.name != after.name || after.version.cmp_precedence(&before.version).is_lt() {
        return Err(invalid(
            "interface comparison requires the same owner and nondecreasing release versions",
        ));
    }
    let compatibility_boundary = !before.version_requirement.matches(&after.version);
    let mut changes = Vec::new();
    let mut report = |path: Vec<String>, reason: &str| {
        changes.push(CompatibilityChange {
            id: String::new(),
            path,
            reason: reason.into(),
            waived: false,
        })
    };
    for (path, previous) in &before.options {
        let Some(next) = after.options.get(path) else {
            report(path.clone(), "public option removed");
            continue;
        };
        compare_type(
            &previous.option_type,
            &next.option_type,
            path,
            &[],
            Direction::Input,
            &mut report,
        );
        if previous.has_default && !next.has_default {
            report(path.clone(), "input default removed");
        }
        if previous.read_only != next.read_only || previous.extensible != next.extensible {
            report(path.clone(), "option authorship rules changed");
        }
    }
    for (path, next) in &after.options {
        if !before.options.contains_key(path) && !next.has_default && !next.read_only {
            report(path.clone(), "required input option added");
        }
    }
    for ((ability, name), previous) in &before.operations {
        let path = vec![
            "aos".into(),
            "abilities".into(),
            ability.clone(),
            "operations".into(),
            name.clone(),
        ];
        let Some(next) = after.operations.get(&(ability.clone(), name.clone())) else {
            report(path, "operation removed from release owner");
            continue;
        };
        let input = child(&path, "input");
        let defaults: Vec<_> = next
            .input_defaults
            .iter()
            .map(|suffix| {
                let mut path = input.clone();
                path.extend(suffix.clone());
                path
            })
            .collect();
        compare_type(
            &previous.input_type,
            &next.input_type,
            &input,
            &defaults,
            Direction::Input,
            &mut report,
        );
        for default in &previous.input_defaults {
            if !next.input_defaults.contains(default) {
                let mut path = input.clone();
                path.extend(default.clone());
                report(path, "input default removed");
            }
        }
        compare_type(
            &previous.result_type,
            &next.result_type,
            &child(&path, "result"),
            &[],
            Direction::Result,
            &mut report,
        );
    }

    let snapshot = serde_json::to_vec(&(before.snapshot(), after.snapshot()))?;
    for change in &mut changes {
        let mut hash = Sha256::new();
        hash.update(&snapshot);
        hash.update(serde_json::to_vec(&(&change.path, &change.reason))?);
        change.id = format!("sha256:{:x}", hash.finalize());
    }
    if exceptions.len() > 1024 {
        return Err(invalid("too many compatibility exceptions"));
    }
    let mut seen = BTreeSet::new();
    for exception in exceptions {
        if exception.reason.trim().is_empty()
            || exception.reason.len() > 4096
            || !seen.insert(&exception.id)
        {
            return Err(invalid(
                "compatibility exceptions require unique IDs and nonempty bounded reasons",
            ));
        }
        let change = changes
            .iter_mut()
            .find(|change| change.id == exception.id)
            .ok_or_else(|| {
                invalid(format!(
                    "stale or unknown compatibility exception '{}'",
                    exception.id
                ))
            })?;
        change.waived = true;
    }
    Ok(CompatibilityReport {
        compatible: compatibility_boundary || changes.iter().all(|change| change.waived),
        compatibility_boundary,
        changes,
    })
}

#[derive(Clone, Copy)]
enum Direction {
    Input,
    Result,
}

fn child(path: &[String], field: &str) -> Vec<String> {
    let mut result = path.to_vec();
    result.push(field.to_owned());
    result
}

// Only fixed records are decomposed. Other changed types are reported as one
// reviewable change rather than attempting a general subtype proof.
fn compare_type(
    previous: &OptionType,
    next: &OptionType,
    path: &[String],
    defaults: &[Vec<String>],
    direction: Direction,
    report: &mut impl FnMut(Vec<String>, &str),
) {
    if previous == next {
        return;
    }
    match (previous, next) {
        (
            OptionType::Submodule {
                fields: old,
                open: old_open,
            },
            OptionType::Submodule {
                fields: new,
                open: new_open,
            },
        ) => {
            if old_open != new_open {
                report(path.to_vec(), "record openness changed");
            }
            for (name, field) in old {
                let path = child(path, name);
                if let Some(next) = new.get(name) {
                    compare_type(field, next, &path, defaults, direction, report);
                } else {
                    report(path, "field removed");
                }
            }
            for name in new.keys().filter(|name| !old.contains_key(*name)) {
                let path = child(path, name);
                match direction {
                    Direction::Input if !defaults.contains(&path) => {
                        report(path, "required input field added")
                    }
                    Direction::Result if !old_open => {
                        report(path, "field added to closed result record")
                    }
                    _ => {}
                }
            }
        }
        _ => report(
            path.to_vec(),
            "type or constraint changed; compatibility requires review",
        ),
    }
}

#[cfg(test)]
mod tests;
