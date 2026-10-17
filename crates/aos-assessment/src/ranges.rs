//! Deterministic advisory interval evaluation with explicit unsupported results.
//!
//! Source ranges retain endpoint order. No lexical fallback, ambient Git graph,
//! or package-name heuristic can turn unsupported evidence into a clean result.

use std::cmp::Ordering;

use anyhow::{Result, bail};

use crate::advisory::{AffectedProduct, AffectedRange, RangeEvent, RangeKind};
use crate::security::AdvisoryVersionScheme;

/// Represents supported applicability facts under three-valued logic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    /// Establishes the source claim under the supplied facts.
    True,
    /// Establishes that the source claim does not apply.
    False,
    /// Cannot establish applicability from supported evidence.
    Unknown,
}

impl Truth {
    /// Applies conjunction, where false dominates uncertainty.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    /// Applies disjunction, where true dominates uncertainty.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }

    /// Applies negation without converting unknown facts to false.
    #[must_use]
    pub const fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Compares versions under one explicitly admitted grammar.
///
/// Semantic versions require all three numeric fields and standard SemVer
/// syntax. Dotted numeric versions contain one to sixteen unsigned decimal
/// components; trailing zero components compare equally. Unsupported ecosystem
/// and Git profiles return `None` instead of guessing an ordering.
///
/// # Errors
///
/// Returns an error for a malformed supported version or numeric overflow.
pub fn compare_versions(
    scheme: AdvisoryVersionScheme,
    left: &str,
    right: &str,
) -> Result<Option<Ordering>> {
    match scheme {
        AdvisoryVersionScheme::Semver => {
            let left = semver::Version::parse(left)?;
            let right = semver::Version::parse(right)?;
            Ok(Some(left.cmp_precedence(&right)))
        }
        AdvisoryVersionScheme::DottedNumeric => {
            let left = numeric(left)?;
            let right = numeric(right)?;
            let width = left.len().max(right.len());
            for index in 0..width {
                let ordering = left
                    .get(index)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&right.get(index).copied().unwrap_or(0));
                if ordering != Ordering::Equal {
                    return Ok(Some(ordering));
                }
            }
            Ok(Some(Ordering::Equal))
        }
        AdvisoryVersionScheme::Ecosystem
        | AdvisoryVersionScheme::Git
        | AdvisoryVersionScheme::Unsupported => Ok(None),
    }
}

/// Evaluates the union of explicit versions and source intervals.
///
/// # Errors
///
/// Returns an error for malformed normalized product/range structure. Invalid
/// comparator inputs remain unknown applicability rather than failing clean.
pub fn affected_version(
    product: &AffectedProduct,
    current: &str,
    scheme: AdvisoryVersionScheme,
) -> Result<Truth> {
    product.validate()?;
    if product.versions.iter().any(|version| version == current) {
        return Ok(Truth::True);
    }
    let mut conclusion = if product.unsupported.is_empty()
        && (!product.versions.is_empty() || !product.ranges.is_empty())
    {
        Truth::False
    } else {
        Truth::Unknown
    };
    for range in &product.ranges {
        conclusion = conclusion.or(affected_range(range, current, scheme)?);
    }
    Ok(conclusion)
}

/// Evaluates OSV interval inclusivity and special introduced-zero semantics.
///
/// # Errors
///
/// Returns an error for structurally malformed endpoints. Unsupported ordering,
/// reversed bounds or invalid version grammars produce unknown applicability.
pub fn affected_range(
    range: &AffectedRange,
    current: &str,
    scheme: AdvisoryVersionScheme,
) -> Result<Truth> {
    range.validate()?;
    let comparator = match (range.kind, scheme) {
        (RangeKind::Semver, AdvisoryVersionScheme::Semver) => AdvisoryVersionScheme::Semver,
        (RangeKind::Ecosystem, AdvisoryVersionScheme::DottedNumeric) => {
            AdvisoryVersionScheme::DottedNumeric
        }
        _ => return Ok(Truth::Unknown),
    };
    let mut lower = None;
    let mut result = Truth::False;
    for event in &range.events {
        match event {
            RangeEvent::Introduced(version) => lower = Some(version.as_str()),
            RangeEvent::Fixed(upper)
            | RangeEvent::Limit(upper)
            | RangeEvent::LastAffected(upper) => {
                let Some(start) = lower.take() else {
                    bail!("range endpoint has no introduced bound");
                };
                let included = interval(
                    comparator,
                    current,
                    start,
                    Some((upper, matches!(event, RangeEvent::LastAffected(_)))),
                );
                result = result.or(included);
            }
        }
    }
    if let Some(start) = lower {
        result = result.or(interval(comparator, current, start, None));
    }
    Ok(result)
}

fn interval(
    scheme: AdvisoryVersionScheme,
    current: &str,
    lower: &str,
    upper: Option<(&str, bool)>,
) -> Truth {
    let valid_current = compare_versions(scheme, current, current);
    if !matches!(valid_current, Ok(Some(_))) {
        return Truth::Unknown;
    }
    if lower != "0" {
        let Ok(Some(ordering)) = compare_versions(scheme, current, lower) else {
            return Truth::Unknown;
        };
        if let Some((upper, _)) = upper {
            let Ok(Some(Ordering::Less | Ordering::Equal)) = compare_versions(scheme, lower, upper)
            else {
                return Truth::Unknown;
            };
        }
        if ordering == Ordering::Less {
            return Truth::False;
        }
    }
    if let Some((upper, inclusive)) = upper {
        let Ok(Some(ordering)) = compare_versions(scheme, current, upper) else {
            return Truth::Unknown;
        };
        if ordering == Ordering::Greater || (ordering == Ordering::Equal && !inclusive) {
            return Truth::False;
        }
    }
    Truth::True
}

fn numeric(value: &str) -> Result<Vec<u64>> {
    if value.is_empty() || value.len() > 256 {
        bail!("invalid dotted numeric advisory version");
    }
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() > 16 {
        bail!("dotted numeric advisory version has too many components");
    }
    parts
        .into_iter()
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("invalid dotted numeric advisory version component");
            }
            Ok(part.parse()?)
        })
        .collect()
}
