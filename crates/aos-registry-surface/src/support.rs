//! Release-train support policy shared by the qualification contract and the
//! signed registry.
//!
//! A stable release version `major.minor.patch` belongs to the train
//! `major.minor`. The policy states, per train, whether it is a standard or
//! long-term-support train and the last day it receives updates. Trains
//! without an explicit entry follow the rolling default: they stay supported
//! until a fixed number of newer stable trains exist.
//!
//! The same document appears in two signed places. The qualification contract
//! exports it under `support`, and the registry's `registry.toml` carries it
//! verbatim as a `[support]` table so consumers and Hubs read the reviewed
//! promise without a second source of truth:
//!
//! ```toml
//! [support.default]
//! kind = "standard"
//! superseded_after_trains = 2
//!
//! [[support.trains]]
//! train = "2026.9"
//! kind = "lts"
//! supported_until = "2028-09-30"
//! ```
//!
//! Everything here is pure and `wasm`-clean: dates are validated and compared
//! with civil-calendar arithmetic rather than a clock crate, and callers pass
//! "today" in explicitly.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Number of days before `supported_until` at which a train is "ending soon".
pub const ENDING_SOON_DAYS: i64 = 90;

/// Support class of a release train.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportKind {
    /// Supported until superseded by newer trains, or until its stated date.
    Standard,
    /// Long-term support with a stated end date.
    Lts,
}

impl SupportKind {
    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Lts => "LTS",
        }
    }
}

/// Rolling rule for trains without an explicit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportDefault {
    /// Support class of implicit trains.
    #[serde(default = "default_kind")]
    pub kind: SupportKind,
    /// Number of newer stable trains after which an implicit train reaches end
    /// of life.
    #[serde(default = "default_superseded_after")]
    pub superseded_after_trains: u32,
}

fn default_kind() -> SupportKind {
    SupportKind::Standard
}

fn default_superseded_after() -> u32 {
    2
}

impl Default for SupportDefault {
    fn default() -> Self {
        Self {
            kind: default_kind(),
            superseded_after_trains: default_superseded_after(),
        }
    }
}

/// Explicit support statement for one train.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportTrain {
    /// The train as `major.minor` without leading zeros.
    pub train: String,
    /// Support class.
    #[serde(default = "default_kind")]
    pub kind: SupportKind,
    /// Last day of support as an ISO-8601 calendar date; absent means until
    /// superseded under the rolling default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_until: Option<String>,
}

/// The complete reviewed support policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SupportPolicy {
    /// Rule for trains without an explicit entry.
    #[serde(default)]
    pub default: SupportDefault,
    /// Explicit per-train statements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trains: Vec<SupportTrain>,
}

/// A policy violation, safe to show to the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportPolicyError(String);

impl fmt::Display for SupportPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SupportPolicyError {}

/// Where a train stands today under the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportState {
    /// Still receiving updates.
    Supported {
        /// Last supported day when the policy states one.
        until: Option<Date>,
    },
    /// Still supported, but within [`ENDING_SOON_DAYS`] of its end date.
    EndingSoon {
        /// Last supported day.
        until: Date,
    },
    /// No longer receiving updates.
    EndOfLife {
        /// Last supported day when the policy stated one.
        until: Option<Date>,
    },
}

impl SupportState {
    /// Whether the train still receives updates.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::EndOfLife { .. })
    }
}

impl SupportPolicy {
    /// Checks train keys, dates, and the LTS end-date rule.
    ///
    /// # Errors
    /// Returns the first violated rule: a malformed train key, a duplicate
    /// train, an invalid date, an LTS train without an end date, or a
    /// rolling count of zero.
    pub fn validate(&self) -> Result<(), SupportPolicyError> {
        if self.default.superseded_after_trains == 0 {
            return Err(SupportPolicyError(
                "support.default.superseded_after_trains must be at least one".into(),
            ));
        }
        let mut seen = Vec::with_capacity(self.trains.len());
        for entry in &self.trains {
            let Some(train) = parse_train(&entry.train) else {
                return Err(SupportPolicyError(format!(
                    "support train {:?} is not major.minor without leading zeros",
                    entry.train
                )));
            };
            if seen.contains(&train) {
                return Err(SupportPolicyError(format!(
                    "support train {} is listed twice",
                    entry.train
                )));
            }
            seen.push(train);
            if let Some(date) = &entry.supported_until {
                if Date::parse(date).is_none() {
                    return Err(SupportPolicyError(format!(
                        "support train {} has an invalid supported_until date {date:?}",
                        entry.train
                    )));
                }
            } else if entry.kind == SupportKind::Lts {
                return Err(SupportPolicyError(format!(
                    "long-term-support train {} must state supported_until",
                    entry.train
                )));
            }
        }
        Ok(())
    }

    /// Returns the explicit entry for a train, if any.
    #[must_use]
    pub fn entry(&self, train: (u64, u64)) -> Option<&SupportTrain> {
        self.trains
            .iter()
            .find(|entry| parse_train(&entry.train) == Some(train))
    }

    /// Returns the support class of a train.
    #[must_use]
    pub fn kind(&self, train: (u64, u64)) -> SupportKind {
        self.entry(train)
            .map_or(self.default.kind, |entry| entry.kind)
    }

    /// Classifies a train given how many newer stable trains exist and today's
    /// date.
    ///
    /// An explicit end date decides on its own. Without one, the train is
    /// supported while fewer than `superseded_after_trains` newer trains
    /// exist. Callers layer channel targeting on top: a train a channel still
    /// points at is supported regardless of this answer.
    #[must_use]
    pub fn classify(&self, train: (u64, u64), newer_trains: usize, today: Date) -> SupportState {
        let until = self
            .entry(train)
            .and_then(|entry| entry.supported_until.as_deref())
            .and_then(Date::parse);
        match until {
            Some(until) => {
                let remaining = until.days() - today.days();
                if remaining < 0 {
                    SupportState::EndOfLife { until: Some(until) }
                } else if remaining <= ENDING_SOON_DAYS {
                    SupportState::EndingSoon { until }
                } else {
                    SupportState::Supported { until: Some(until) }
                }
            }
            None => {
                if newer_trains < self.default.superseded_after_trains as usize {
                    SupportState::Supported { until: None }
                } else {
                    SupportState::EndOfLife { until: None }
                }
            }
        }
    }
}

/// Parses `major.minor` without leading zeros.
#[must_use]
pub fn parse_train(text: &str) -> Option<(u64, u64)> {
    let (major, minor) = text.split_once('.')?;
    let field = |value: &str| -> Option<u64> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return None;
        }
        value.parse().ok()
    };
    Some((field(major)?, field(minor)?))
}

/// A proleptic-Gregorian calendar date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: i64,
    month: u8,
    day: u8,
}

impl Date {
    /// Parses `YYYY-MM-DD`, rejecting impossible days.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let number = |slice: &str| -> Option<i64> {
            slice
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| slice.parse().ok())
                .flatten()
        };
        let year = number(&text[0..4])?;
        let month = u8::try_from(number(&text[5..7])?).ok()?;
        let day = u8::try_from(number(&text[8..10])?).ok()?;
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// Converts a Unix timestamp (seconds) to its UTC calendar date.
    #[must_use]
    pub fn from_unix(secs: i64) -> Self {
        Self::from_days(secs.div_euclid(86_400))
    }

    /// Converts days since 1970-01-01 to a calendar date using Howard
    /// Hinnant's civil-from-days algorithm.
    #[must_use]
    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        Self {
            year: y,
            month: m as u8,
            day: d as u8,
        }
    }

    /// Days since 1970-01-01 (negative before the epoch).
    #[must_use]
    pub fn days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(self.month);
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SupportPolicy {
        SupportPolicy {
            default: SupportDefault::default(),
            trains: vec![
                SupportTrain {
                    train: "2026.9".into(),
                    kind: SupportKind::Lts,
                    supported_until: Some("2028-09-30".into()),
                },
                SupportTrain {
                    train: "2026.3".into(),
                    kind: SupportKind::Standard,
                    supported_until: Some("2026-06-30".into()),
                },
            ],
        }
    }

    #[test]
    fn dates_round_trip_and_reject_impossible_days() {
        for text in [
            "1970-01-01",
            "2000-02-29",
            "2026-09-05",
            "2028-09-30",
            "1969-12-31",
        ] {
            let date = Date::parse(text).unwrap();
            assert_eq!(Date::from_days(date.days()), date, "{text}");
            assert_eq!(date.to_string(), text);
        }
        assert_eq!(Date::from_unix(1_788_626_655).to_string(), "2026-09-05");
        for bad in [
            "2026-02-30",
            "2025-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-9-5",
            "20260905",
        ] {
            assert!(Date::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn trains_parse_without_leading_zeros() {
        assert_eq!(parse_train("2026.9"), Some((2026, 9)));
        assert_eq!(parse_train("0.1"), Some((0, 1)));
        assert_eq!(parse_train("2026.09"), None);
        assert_eq!(parse_train("2026"), None);
        assert_eq!(parse_train("2026.9.1"), None);
    }

    #[test]
    fn validation_enforces_keys_dates_and_lts_end_dates() {
        policy().validate().unwrap();
        let mut broken = policy();
        broken.trains[0].supported_until = None;
        assert!(broken
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must state"));
        let mut broken = policy();
        broken.trains[1].train = "2026.03".into();
        assert!(broken.validate().is_err());
        let mut broken = policy();
        broken.trains[1].supported_until = Some("2026-06-31".into());
        assert!(broken.validate().is_err());
        let mut broken = policy();
        broken.trains.push(broken.trains[0].clone());
        assert!(broken.validate().unwrap_err().to_string().contains("twice"));
        let mut broken = policy();
        broken.default.superseded_after_trains = 0;
        assert!(broken.validate().is_err());
    }

    #[test]
    fn classification_follows_dates_then_the_rolling_default() {
        let policy = policy();
        let today = Date::parse("2026-09-05").unwrap();
        assert_eq!(
            policy.classify((2026, 9), 0, today),
            SupportState::Supported {
                until: Date::parse("2028-09-30")
            }
        );
        assert_eq!(policy.kind((2026, 9)), SupportKind::Lts);
        assert_eq!(
            policy.classify((2026, 3), 3, today),
            SupportState::EndOfLife {
                until: Date::parse("2026-06-30")
            }
        );
        assert_eq!(
            policy.classify((2026, 9), 5, Date::parse("2028-08-01").unwrap()),
            SupportState::EndingSoon {
                until: Date::parse("2028-09-30").unwrap()
            }
        );
        assert_eq!(
            policy.classify((2026, 8), 1, today),
            SupportState::Supported { until: None }
        );
        assert_eq!(
            policy.classify((2026, 7), 2, today),
            SupportState::EndOfLife { until: None }
        );
        assert_eq!(policy.kind((2026, 7)), SupportKind::Standard);
    }

    #[test]
    fn toml_and_json_forms_agree() {
        let toml_text = r#"
[default]
kind = "standard"
superseded_after_trains = 2

[[trains]]
train = "2026.9"
kind = "lts"
supported_until = "2028-09-30"

[[trains]]
train = "2026.3"
supported_until = "2026-06-30"
"#;
        let from_toml: SupportPolicy = toml::from_str(toml_text).unwrap();
        assert_eq!(from_toml, policy());
        let json = serde_json::to_string(&from_toml).unwrap();
        assert_eq!(
            json,
            r#"{"default":{"kind":"standard","superseded_after_trains":2},"trains":[{"train":"2026.9","kind":"lts","supported_until":"2028-09-30"},{"train":"2026.3","kind":"standard","supported_until":"2026-06-30"}]}"#
        );
        let empty: SupportPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, SupportPolicy::default());
        assert!(toml::from_str::<SupportPolicy>("[default]\nsurprise = 1\n").is_err());
    }
}
