//! Deterministic cache-retention selector evaluation.
//!
//! RFC-0012 deliberately does not delegate retention expressions to a host
//! package manager or a library-specific shorthand grammar. This module owns
//! the portable comparator-only SemVer language and the stable recent-release
//! ordering used to materialize provenance-bearing cache roots on native Hub
//! and Worker runtimes.

use std::cmp::Ordering;
use thiserror::Error;

/// A canonical SemVer 2.0.0 value with unbounded numeric identifiers.
///
/// SemVer does not impose an integer-size limit. Core and numeric prerelease
/// identifiers therefore remain decimal strings and compare by length then
/// bytes instead of being narrowed to a machine integer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalSemver {
    core: [String; 3],
    prerelease: Vec<PrereleaseIdentifier>,
    canonical: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PrereleaseIdentifier {
    Numeric(String),
    Alphanumeric(String),
}

impl CanonicalSemver {
    /// Parses one complete SemVer 2.0.0 value.
    ///
    /// # Errors
    ///
    /// Returns [`SemverValueError`] when the value is partial, contains an
    /// invalid identifier, or gives a leading zero to a core or numeric
    /// prerelease identifier.
    pub fn parse(value: &str) -> Result<Self, SemverValueError> {
        if value.is_empty() || !value.is_ascii() {
            return Err(SemverValueError);
        }
        let without_build = match value.split_once('+') {
            Some((version, build)) => {
                parse_build_identifiers(build)?;
                version
            }
            None => value,
        };
        let (core, prerelease) = match without_build.split_once('-') {
            Some((core, prerelease)) => (core, parse_prerelease_identifiers(prerelease)?),
            None => (without_build, Vec::new()),
        };
        let mut components = core.split('.');
        let major = parse_numeric_identifier(components.next().ok_or(SemverValueError)?)?;
        let minor = parse_numeric_identifier(components.next().ok_or(SemverValueError)?)?;
        let patch = parse_numeric_identifier(components.next().ok_or(SemverValueError)?)?;
        if components.next().is_some() {
            return Err(SemverValueError);
        }
        Ok(Self {
            core: [major, minor, patch],
            prerelease,
            canonical: value.to_string(),
        })
    }

    /// Returns the canonical SemVer spelling.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Reports whether this value contains a prerelease component.
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }

    /// Compares SemVer precedence while ignoring build metadata.
    #[must_use]
    pub fn cmp_precedence(&self, other: &Self) -> Ordering {
        for (left, right) in self.core.iter().zip(&other.core) {
            let ordering = compare_decimal(left, right);
            if !ordering.is_eq() {
                return ordering;
            }
        }
        match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_prerelease(&self.prerelease, &other.prerelease),
        }
    }
}

/// An invalid complete SemVer 2.0.0 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid complete SemVer 2.0.0 value")]
pub struct SemverValueError;

/// One canonical comparator operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparatorOperator {
    /// Strictly less than.
    Less,
    /// Less than or equal.
    LessOrEqual,
    /// Equal in SemVer precedence; build metadata is ignored.
    Equal,
    /// Strictly greater than.
    Greater,
    /// Greater than or equal.
    GreaterOrEqual,
}

impl ComparatorOperator {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Less => "<",
            Self::LessOrEqual => "<=",
            Self::Equal => "=",
            Self::Greater => ">",
            Self::GreaterOrEqual => ">=",
        }
    }

    fn matches(self, candidate: &CanonicalSemver, required: &CanonicalSemver) -> bool {
        let precedence = candidate.cmp_precedence(required);
        match self {
            Self::Less => precedence.is_lt(),
            Self::LessOrEqual => !precedence.is_gt(),
            Self::Equal => precedence.is_eq(),
            Self::Greater => precedence.is_gt(),
            Self::GreaterOrEqual => !precedence.is_lt(),
        }
    }
}

/// One canonical operator/version comparator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RetentionComparator {
    operator: ComparatorOperator,
    version: CanonicalSemver,
}

impl RetentionComparator {
    /// Returns the comparator operator.
    #[must_use]
    pub const fn operator(&self) -> ComparatorOperator {
        self.operator
    }

    /// Returns the exact canonical version.
    #[must_use]
    pub const fn version(&self) -> &CanonicalSemver {
        &self.version
    }

    fn canonical(&self) -> String {
        format!("{}{}", self.operator.as_str(), self.version.canonical())
    }
}

/// A parsed, canonical comparator-only SemVer retention requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionSemverRequirement {
    conjunctions: Vec<Vec<RetentionComparator>>,
    canonical: String,
}

impl RetentionSemverRequirement {
    /// Parses and canonicalizes the RFC-0012 SemVer selector grammar.
    ///
    /// # Errors
    ///
    /// Returns [`RetentionRequirementError`] for empty terms, unsupported
    /// shorthand, non-OWS whitespace, a missing explicit comparator, build
    /// metadata, or an invalid complete SemVer 2.0.0 version.
    pub fn parse(expression: &str) -> Result<Self, RetentionRequirementError> {
        if expression
            .chars()
            .any(|character| character.is_whitespace() && character != ' ' && character != '\t')
        {
            return Err(RetentionRequirementError::InvalidWhitespace);
        }
        let expression = trim_ows(expression);
        if expression.is_empty() {
            return Err(RetentionRequirementError::EmptyExpression);
        }

        let mut conjunctions = Vec::new();
        for raw_conjunction in expression.split("||") {
            let raw_conjunction = trim_ows(raw_conjunction);
            if raw_conjunction.is_empty() {
                return Err(RetentionRequirementError::EmptyConjunction);
            }
            let mut comparators = Vec::new();
            for raw_comparator in raw_conjunction.split(',') {
                let raw_comparator = trim_ows(raw_comparator);
                if raw_comparator.is_empty() {
                    return Err(RetentionRequirementError::EmptyComparator);
                }
                comparators.push(parse_comparator(raw_comparator)?);
            }
            comparators.sort_by(|left, right| {
                left.operator
                    .as_str()
                    .cmp(right.operator.as_str())
                    .then_with(|| {
                        left.version
                            .canonical()
                            .as_bytes()
                            .cmp(right.version.canonical().as_bytes())
                    })
            });
            comparators.dedup();
            conjunctions.push(comparators);
        }

        conjunctions.sort_by_cached_key(|conjunction| canonical_conjunction(conjunction));
        let canonical = conjunctions
            .iter()
            .map(|conjunction| canonical_conjunction(conjunction))
            .collect::<Vec<_>>()
            .join("||");
        Ok(Self {
            conjunctions,
            canonical,
        })
    }

    /// Returns the canonical expression stored in selector digests.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Reports whether a candidate satisfies the requirement.
    ///
    /// Prerelease filtering occurs before comparator evaluation, exactly as
    /// RFC-0012 specifies; SemVer precedence ignores build metadata.
    #[must_use]
    pub fn matches(&self, candidate: &CanonicalSemver, include_prereleases: bool) -> bool {
        if !include_prereleases && candidate.is_prerelease() {
            return false;
        }
        self.conjunctions.iter().any(|conjunction| {
            conjunction
                .iter()
                .all(|comparator| comparator.operator.matches(candidate, &comparator.version))
        })
    }

    /// Returns the canonical conjunction/comparator structure.
    #[must_use]
    pub fn conjunctions(&self) -> &[Vec<RetentionComparator>] {
        &self.conjunctions
    }
}

/// A malformed retention SemVer requirement.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RetentionRequirementError {
    /// No expression remained after OWS trimming.
    #[error("SemVer retention requirement is empty")]
    EmptyExpression,
    /// An OR branch was empty.
    #[error("SemVer retention requirement contains an empty conjunction")]
    EmptyConjunction,
    /// A comma-delimited comparator was empty.
    #[error("SemVer retention requirement contains an empty comparator")]
    EmptyComparator,
    /// Whitespace other than SP/HTAB was used.
    #[error("SemVer retention requirement permits only space and tab whitespace")]
    InvalidWhitespace,
    /// No explicit comparator operator was present.
    #[error("SemVer retention comparator requires one of >=, <=, =, >, <")]
    MissingOperator,
    /// OWS occurred between an operator and version.
    #[error("SemVer retention comparator cannot contain whitespace after its operator")]
    OperatorWhitespace,
    /// Build metadata is forbidden in requirement versions.
    #[error("SemVer retention requirement versions cannot contain build metadata")]
    BuildMetadata,
    /// The version was not complete canonical SemVer 2.0.0.
    #[error("invalid SemVer retention version '{version}': {detail}")]
    InvalidVersion {
        /// Rejected version text.
        version: String,
        /// Parser diagnostic.
        detail: String,
    },
}

/// A verified release candidate for `recent_releases` selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    /// Stable positive release identity, compared as unsigned big-endian bytes.
    pub release_id: u64,
    /// Immutable release tag spelling.
    pub tag: String,
    /// Verified tag object id with a canonical algorithm tag.
    pub verified_tag_oid: CanonicalGitObjectId,
    /// Immutable verified tag timestamp in Unix seconds.
    pub tagged_at: i64,
    /// Whether tag verification succeeded.
    pub verified: bool,
    /// Whether the release owns a complete immutable artifact snapshot.
    pub complete_artifact_snapshot: bool,
}

/// A canonical Git object id used as a deterministic retention tie-breaker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalGitObjectId {
    algorithm: GitObjectIdAlgorithm,
    digest: Vec<u8>,
}

/// The supported Git object-id algorithms in canonical sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitObjectIdAlgorithm {
    /// A twenty-byte SHA-1 object id.
    Sha1,
    /// A thirty-two-byte SHA-256 object id.
    Sha256,
}

impl GitObjectIdAlgorithm {
    const fn sort_tag(self) -> u8 {
        match self {
            Self::Sha1 => 0x01,
            Self::Sha256 => 0x02,
        }
    }
}

impl CanonicalGitObjectId {
    /// Constructs an object id from its algorithm and raw digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`GitObjectIdError`] when the digest length is not twenty bytes
    /// for SHA-1 or thirty-two bytes for SHA-256.
    pub fn new(algorithm: GitObjectIdAlgorithm, digest: Vec<u8>) -> Result<Self, GitObjectIdError> {
        let expected = match algorithm {
            GitObjectIdAlgorithm::Sha1 => 20,
            GitObjectIdAlgorithm::Sha256 => 32,
        };
        if digest.len() != expected {
            return Err(GitObjectIdError);
        }
        Ok(Self { algorithm, digest })
    }

    /// Returns the object-id algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> GitObjectIdAlgorithm {
        self.algorithm
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.algorithm
            .sort_tag()
            .cmp(&other.algorithm.sort_tag())
            .then_with(|| self.digest.cmp(&other.digest))
    }
}

/// An object id whose byte length disagrees with its Git hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Git object-id digest length does not match its algorithm")]
pub struct GitObjectIdError;

/// An invalid recent-release selector.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecentReleaseError {
    /// Count must be within the public contract.
    #[error("recent release count must be from 1 through 100")]
    InvalidCount,
}

/// Selects recent verified releases using RFC-0012's stable ordering tuple.
///
/// Invalid/non-SemVer tags and incomplete or unverified releases are excluded.
///
/// # Errors
///
/// Returns [`RecentReleaseError::InvalidCount`] unless `count` is in `1..=100`.
pub fn select_recent_releases<'a>(
    releases: &'a [VerifiedRelease],
    count: u32,
    include_prereleases: bool,
) -> Result<Vec<&'a VerifiedRelease>, RecentReleaseError> {
    if !(1..=100).contains(&count) {
        return Err(RecentReleaseError::InvalidCount);
    }
    let mut eligible = releases
        .iter()
        .filter(|release| {
            release.release_id != 0 && release.verified && release.complete_artifact_snapshot
        })
        .filter_map(|release| {
            CanonicalSemver::parse(&release.tag)
                .ok()
                .filter(|version| include_prereleases || !version.is_prerelease())
                .map(|version| (release, version))
        })
        .collect::<Vec<_>>();
    eligible.sort_by(
        |(left_release, left_version), (right_release, right_version)| {
            right_release
                .tagged_at
                .cmp(&left_release.tagged_at)
                .then_with(|| right_version.cmp_precedence(left_version))
                .then_with(|| {
                    left_version
                        .canonical()
                        .as_bytes()
                        .cmp(right_version.canonical().as_bytes())
                })
                .then_with(|| {
                    left_release
                        .verified_tag_oid
                        .cmp_canonical(&right_release.verified_tag_oid)
                })
                .then_with(|| left_release.release_id.cmp(&right_release.release_id))
        },
    );
    Ok(eligible
        .into_iter()
        .take(count as usize)
        .map(|(release, _version)| release)
        .collect())
}

fn parse_comparator(value: &str) -> Result<RetentionComparator, RetentionRequirementError> {
    let (operator, version) = if let Some(version) = value.strip_prefix(">=") {
        (ComparatorOperator::GreaterOrEqual, version)
    } else if let Some(version) = value.strip_prefix("<=") {
        (ComparatorOperator::LessOrEqual, version)
    } else if let Some(version) = value.strip_prefix('=') {
        (ComparatorOperator::Equal, version)
    } else if let Some(version) = value.strip_prefix('>') {
        (ComparatorOperator::Greater, version)
    } else if let Some(version) = value.strip_prefix('<') {
        (ComparatorOperator::Less, version)
    } else {
        return Err(RetentionRequirementError::MissingOperator);
    };
    if version.starts_with(' ') || version.starts_with('\t') {
        return Err(RetentionRequirementError::OperatorWhitespace);
    }
    if version.contains('+') {
        return Err(RetentionRequirementError::BuildMetadata);
    }
    let parsed = CanonicalSemver::parse(version).map_err(|error| {
        RetentionRequirementError::InvalidVersion {
            version: version.to_string(),
            detail: error.to_string(),
        }
    })?;
    Ok(RetentionComparator {
        operator,
        version: parsed,
    })
}

fn canonical_conjunction(comparators: &[RetentionComparator]) -> String {
    comparators
        .iter()
        .map(RetentionComparator::canonical)
        .collect::<Vec<_>>()
        .join(",")
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn parse_numeric_identifier(value: &str) -> Result<String, SemverValueError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(SemverValueError);
    }
    Ok(value.to_string())
}

fn parse_prerelease_identifiers(
    value: &str,
) -> Result<Vec<PrereleaseIdentifier>, SemverValueError> {
    parse_dot_identifiers(value, true)?
        .into_iter()
        .map(|identifier| {
            if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                parse_numeric_identifier(identifier).map(PrereleaseIdentifier::Numeric)
            } else {
                Ok(PrereleaseIdentifier::Alphanumeric(identifier.to_string()))
            }
        })
        .collect()
}

fn parse_build_identifiers(value: &str) -> Result<(), SemverValueError> {
    parse_dot_identifiers(value, false).map(|_| ())
}

fn parse_dot_identifiers(value: &str, _prerelease: bool) -> Result<Vec<&str>, SemverValueError> {
    if value.is_empty() {
        return Err(SemverValueError);
    }
    let identifiers = value.split('.').collect::<Vec<_>>();
    if identifiers.iter().any(|identifier| {
        identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(SemverValueError);
    }
    Ok(identifiers)
}

fn compare_decimal(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn compare_prerelease(left: &[PrereleaseIdentifier], right: &[PrereleaseIdentifier]) -> Ordering {
    for (left_identifier, right_identifier) in left.iter().zip(right) {
        let ordering = match (left_identifier, right_identifier) {
            (PrereleaseIdentifier::Numeric(left), PrereleaseIdentifier::Numeric(right)) => {
                compare_decimal(left, right)
            }
            (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alphanumeric(_)) => {
                Ordering::Less
            }
            (PrereleaseIdentifier::Alphanumeric(_), PrereleaseIdentifier::Numeric(_)) => {
                Ordering::Greater
            }
            (
                PrereleaseIdentifier::Alphanumeric(left),
                PrereleaseIdentifier::Alphanumeric(right),
            ) => left.as_bytes().cmp(right.as_bytes()),
        };
        if !ordering.is_eq() {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_canonicalization_is_stable_and_deduplicates_comparators() {
        let requirement =
            RetentionSemverRequirement::parse("  >=2.0.0, <3.0.0,>=2.0.0 || =1.5.0\t").unwrap();
        assert_eq!(requirement.canonical(), "<3.0.0,>=2.0.0||=1.5.0");
        assert!(requirement.matches(&CanonicalSemver::parse("2.5.0").unwrap(), false));
        assert!(requirement.matches(&CanonicalSemver::parse("1.5.0").unwrap(), false));
        assert!(!requirement.matches(&CanonicalSemver::parse("3.0.0").unwrap(), false));
    }

    #[test]
    fn requirement_rejects_every_unsupported_shorthand() {
        for expression in [
            "1.2.3",
            "^1.2.3",
            "~1.2.3",
            "=1.2",
            "=1.*",
            "=1.2.3 - =2.0.0",
            ">=1.0.0 <2.0.0",
            ">= 1.0.0",
            "=1.0.0+build",
            "=01.0.0",
            ">=1.0.0\n",
            "=1.0.0||",
            ",=1.0.0",
        ] {
            assert!(
                RetentionSemverRequirement::parse(expression).is_err(),
                "{expression}"
            );
        }
    }

    #[test]
    fn prerelease_filter_is_explicit() {
        let requirement = RetentionSemverRequirement::parse(">=1.0.0-alpha").unwrap();
        let candidate = CanonicalSemver::parse("1.0.0-beta").unwrap();
        assert!(!requirement.matches(&candidate, false));
        assert!(requirement.matches(&candidate, true));
    }

    #[test]
    fn semver_numeric_identifiers_are_not_machine_integer_bounded() {
        let lower =
            CanonicalSemver::parse("18446744073709551616.0.0-99999999999999999999").unwrap();
        let higher =
            CanonicalSemver::parse("18446744073709551616.0.0-100000000000000000000").unwrap();
        assert!(lower.cmp_precedence(&higher).is_lt());
        let requirement = RetentionSemverRequirement::parse(">=18446744073709551616.0.0").unwrap();
        assert!(requirement.matches(
            &CanonicalSemver::parse("18446744073709551617.0.0").unwrap(),
            false,
        ));
    }

    #[test]
    fn semver_precedence_matches_the_normative_chain() {
        let values = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        .map(|value| CanonicalSemver::parse(value).unwrap());
        for pair in values.windows(2) {
            assert!(pair[0].cmp_precedence(&pair[1]).is_lt());
        }
    }

    #[test]
    fn recent_release_order_uses_the_normative_tuple() {
        let release = |id: u8, tag: &str, tagged_at: i64, oid: u8| VerifiedRelease {
            release_id: u64::from(id),
            tag: tag.to_string(),
            verified_tag_oid: CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha1, vec![oid; 20])
                .unwrap(),
            tagged_at,
            verified: true,
            complete_artifact_snapshot: true,
        };
        let releases = vec![
            release(4, "9.0.0", 99, 4),
            release(3, "2.0.0+z", 100, 3),
            release(2, "2.0.0+a", 100, 2),
            release(1, "1.9.0", 100, 1),
            release(5, "3.0.0-alpha", 101, 5),
        ];
        let selected = select_recent_releases(&releases, 4, false).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|release| release.release_id)
                .collect::<Vec<_>>(),
            vec![2, 3, 1, 4]
        );
        let selected = select_recent_releases(&releases, 1, true).unwrap();
        assert_eq!(selected[0].release_id, 5);
    }

    #[test]
    fn recent_release_selector_rejects_invalid_count_and_state() {
        let object_id =
            || CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha1, vec![1; 20]).unwrap();
        let releases = vec![
            VerifiedRelease {
                release_id: 1,
                tag: "1.0.0".to_string(),
                verified_tag_oid: object_id(),
                tagged_at: 1,
                verified: false,
                complete_artifact_snapshot: true,
            },
            VerifiedRelease {
                release_id: 2,
                tag: "2.0.0".to_string(),
                verified_tag_oid: object_id(),
                tagged_at: 2,
                verified: true,
                complete_artifact_snapshot: false,
            },
            VerifiedRelease {
                release_id: 3,
                tag: "not-semver".to_string(),
                verified_tag_oid: object_id(),
                tagged_at: 3,
                verified: true,
                complete_artifact_snapshot: true,
            },
        ];
        assert_eq!(
            select_recent_releases(&releases, 0, false),
            Err(RecentReleaseError::InvalidCount)
        );
        assert_eq!(
            select_recent_releases(&releases, 101, false),
            Err(RecentReleaseError::InvalidCount)
        );
        assert!(select_recent_releases(&releases, 1, false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn git_object_ids_have_one_validated_canonical_byte_order() {
        assert!(CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha1, vec![0; 19]).is_err());
        assert!(CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha256, vec![0; 31]).is_err());
        let sha1 = CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha1, vec![0xff; 20]).unwrap();
        let sha256 = CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha256, vec![0; 32]).unwrap();
        assert!(sha1.cmp_canonical(&sha256).is_lt());
    }

    #[test]
    fn recent_release_final_ties_use_oid_then_unsigned_release_id() {
        let oid =
            |byte| CanonicalGitObjectId::new(GitObjectIdAlgorithm::Sha1, vec![byte; 20]).unwrap();
        let releases = vec![
            VerifiedRelease {
                release_id: 3,
                tag: "1.0.0".into(),
                verified_tag_oid: oid(2),
                tagged_at: 1,
                verified: true,
                complete_artifact_snapshot: true,
            },
            VerifiedRelease {
                release_id: 2,
                tag: "1.0.0".into(),
                verified_tag_oid: oid(1),
                tagged_at: 1,
                verified: true,
                complete_artifact_snapshot: true,
            },
            VerifiedRelease {
                release_id: 1,
                tag: "1.0.0".into(),
                verified_tag_oid: oid(1),
                tagged_at: 1,
                verified: true,
                complete_artifact_snapshot: true,
            },
        ];
        assert_eq!(
            select_recent_releases(&releases, 3, false)
                .unwrap()
                .into_iter()
                .map(|release| release.release_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3],
        );
    }

    #[test]
    fn operator_string_sort_order_is_normative_lexical_order() {
        let mut operators = [
            ComparatorOperator::GreaterOrEqual,
            ComparatorOperator::Equal,
            ComparatorOperator::LessOrEqual,
            ComparatorOperator::Greater,
            ComparatorOperator::Less,
        ];
        operators.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(
            operators.map(ComparatorOperator::as_str),
            ["<", "<=", "=", ">", ">="]
        );
    }
}
