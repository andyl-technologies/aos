//! The crawl-policy value type shared by both hub shells.
//!
//! A crawl policy governs whether (and which) automated crawlers may index a
//! registry or the instance root, surfaced to clients as the generated
//! `robots.txt` rendered by [`crate::robots`]. The same three-valued policy
//! applies per-registry (stored in the `registries.crawl_policy` column) and at
//! the instance root (stored under the `root_crawl_policy` instance-config key),
//! so one type and one renderer serve both the native hub and the Cloudflare
//! Worker.
//!
//! # Wire form
//!
//! A policy round-trips through a stable lowercase string (the value stored in
//! the database and accepted on the CLI / Connect API):
//!
//! ```text
//! allow_all     every crawler may index everything
//! allow_no_ai   general crawlers may index; known AI crawlers are disallowed
//! deny_all       no crawler may index anything
//! ```

/// Which crawlers a registry or the instance root admits.
///
/// The value backing the generated `robots.txt` (see
/// [`crate::robots::render_robots`]). It is deliberately a closed, three-valued
/// enum rather than a free-form `robots.txt` body so the policy is auditable and
/// the same control renders consistently across both shells; an operator who
/// needs a bespoke document sets a custom `robots.txt` override instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlPolicy {
    /// Every crawler may index everything (`User-agent: *` / `Allow: /`).
    AllowAll,
    /// General crawlers may index, but every known AI crawler is disallowed.
    AllowNoAi,
    /// No crawler may index anything (`User-agent: *` / `Disallow: /`).
    DenyAll,
}

impl CrawlPolicy {
    /// The wire string stored in the database and accepted on the CLI / API.
    ///
    /// The inverse of [`CrawlPolicy::parse`] for the three valid values.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CrawlPolicy::AllowAll => "allow_all",
            CrawlPolicy::AllowNoAi => "allow_no_ai",
            CrawlPolicy::DenyAll => "deny_all",
        }
    }

    /// Parse a stored or operator-supplied policy string.
    ///
    /// Accepts exactly the three wire strings (`allow_all`, `allow_no_ai`,
    /// `deny_all`). Unlike a fail-closed read, this is *strict*: an unknown
    /// value is rejected with `Err` so a typo on the CLI or API surfaces as an
    /// error rather than silently changing the posture.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the offending value when `s` is not one of the three
    /// recognized policy strings.
    pub fn parse(s: &str) -> Result<CrawlPolicy, InvalidCrawlPolicy> {
        match s {
            "allow_all" => Ok(CrawlPolicy::AllowAll),
            "allow_no_ai" => Ok(CrawlPolicy::AllowNoAi),
            "deny_all" => Ok(CrawlPolicy::DenyAll),
            other => Err(InvalidCrawlPolicy(other.to_string())),
        }
    }

    /// Parse a stored policy string, defaulting to [`CrawlPolicy::AllowAll`].
    ///
    /// The lenient read used on serving paths where a malformed stored value
    /// must never break the response: any unrecognized value (a corrupt row, or
    /// a value written by a future, unknown version) falls back to the default
    /// permissive posture rather than erroring.
    #[must_use]
    pub fn parse_or_default(s: &str) -> CrawlPolicy {
        CrawlPolicy::parse(s).unwrap_or(CrawlPolicy::AllowAll)
    }
}

impl Default for CrawlPolicy {
    /// The default posture: [`CrawlPolicy::AllowAll`].
    fn default() -> Self {
        CrawlPolicy::AllowAll
    }
}

/// The error returned by [`CrawlPolicy::parse`] for an unrecognized value.
///
/// Carries the rejected string so the caller can echo it in a CLI / API error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCrawlPolicy(pub String);

impl std::fmt::Display for InvalidCrawlPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid crawl policy '{}': allow_all, allow_no_ai, or deny_all",
            self.0
        )
    }
}

impl std::error::Error for InvalidCrawlPolicy {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_variant() {
        for policy in [
            CrawlPolicy::AllowAll,
            CrawlPolicy::AllowNoAi,
            CrawlPolicy::DenyAll,
        ] {
            assert_eq!(CrawlPolicy::parse(policy.as_str()), Ok(policy));
        }
    }

    #[test]
    fn parse_rejects_unknown() {
        let err = CrawlPolicy::parse("nonsense").unwrap_err();
        assert_eq!(err, InvalidCrawlPolicy("nonsense".to_string()));
        assert!(err.to_string().contains("nonsense"));
    }

    #[test]
    fn parse_or_default_is_lenient() {
        assert_eq!(
            CrawlPolicy::parse_or_default("deny_all"),
            CrawlPolicy::DenyAll
        );
        assert_eq!(
            CrawlPolicy::parse_or_default("garbage"),
            CrawlPolicy::AllowAll
        );
        assert_eq!(CrawlPolicy::parse_or_default(""), CrawlPolicy::AllowAll);
    }

    #[test]
    fn default_is_allow_all() {
        assert_eq!(CrawlPolicy::default(), CrawlPolicy::AllowAll);
    }
}
