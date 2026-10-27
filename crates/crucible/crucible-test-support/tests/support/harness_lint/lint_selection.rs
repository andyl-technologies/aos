//! Validates selector structure and computes guarantees across lint branches.
//!
//! Metadata keeps concatenated selector elements in declaration order:
//!
//! ```json
//! {"type":"SELECTOR_LIST","elements":[[
//!   {"condition":"//conditions:default","values":{"unwrap_used":"deny"}}
//! ]]}
//! ```
//!
//! Dictionary concatenation replaces earlier keys. A union of observed levels
//! cannot establish that the final level is strict on every branch.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// Retains a literal value or ordered selector elements.
#[derive(serde::Deserialize)]
pub(super) struct Selection<T> {
    /// Names the literal attribute type or `SELECTOR_LIST`.
    #[serde(rename = "type")]
    kind: String,
    values: Option<T>,
    elements: Option<Vec<Vec<Alternative<T>>>>,
}

#[derive(serde::Deserialize)]
struct Alternative<T> {
    condition: String,
    values: T,
}

impl<T> Selection<T> {
    /// Checks the literal type and rejects ambiguous or empty selectors.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong types, mixed representations, empty elements,
    /// or repeated conditions within an element.
    pub(super) fn validate(&self, expected: &str) -> io::Result<()> {
        if self.kind == expected && self.values.is_some() && self.elements.is_none() {
            return Ok(());
        }
        let Some(elements) = &self.elements else {
            return Err(io::Error::other("invalid declared lint selection"));
        };
        if self.kind != "SELECTOR_LIST" || self.values.is_some() || elements.is_empty() {
            return Err(io::Error::other("invalid declared lint selection"));
        }
        for element in elements {
            let mut conditions = BTreeSet::new();
            if element.is_empty()
                || element.iter().any(|branch| {
                    !branch.condition.starts_with("//") || !conditions.insert(&branch.condition)
                })
            {
                return Err(io::Error::other("invalid declared lint selector branches"));
            }
        }
        Ok(())
    }

    /// Visits every declared value without inferring a branch guarantee.
    pub(super) fn alternatives(&self) -> Vec<&T> {
        if let Some(values) = &self.values {
            return vec![values];
        }
        self.elements
            .iter()
            .flatten()
            .flatten()
            .map(|branch| &branch.values)
            .collect()
    }
}

impl Selection<Vec<String>> {
    /// Returns the union of values for ownership and conservative policy checks.
    pub(super) fn union(&self) -> BTreeSet<&str> {
        self.alternatives()
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    /// Returns values present on every alternative of the concatenated list.
    pub(super) fn guaranteed(&self) -> BTreeSet<&str> {
        if let Some(values) = &self.values {
            return values.iter().map(String::as_str).collect();
        }
        let mut result = BTreeSet::new();
        for element in self.elements.iter().flatten() {
            let mut alternatives = element.iter();
            let Some(first) = alternatives.next() else {
                continue;
            };
            let mut common: BTreeSet<_> = first.values.iter().map(String::as_str).collect();
            for branch in alternatives {
                common.retain(|value| branch.values.iter().any(|item| item.as_str() == *value));
            }
            result.extend(common);
        }
        result
    }
}

impl Selection<BTreeMap<String, String>> {
    /// Checks final dictionary levels after every possible ordered override.
    pub(super) fn guarantees_deny(&self, lint: &str) -> bool {
        if let Some(values) = &self.values {
            return values.get(lint).is_some_and(|level| strict(level));
        }
        let mut levels = BTreeSet::from([None]);
        for element in self.elements.iter().flatten() {
            levels = levels
                .iter()
                .flat_map(|previous| {
                    element.iter().map(move |branch| {
                        branch.values.get(lint).map(String::as_str).or(*previous)
                    })
                })
                .collect();
        }
        !levels.is_empty() && levels.into_iter().all(|level| level.is_some_and(strict))
    }
}

fn strict(level: &str) -> bool {
    matches!(level, "deny" | "forbid")
}
