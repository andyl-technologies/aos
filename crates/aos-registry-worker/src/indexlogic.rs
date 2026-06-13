//! Pure, native-testable verification decisions for the Cron indexer.
//!
//! The Worker's indexer ([`crate::indexer`]) is wasm32-only — it is welded to
//! the async D1/R2 bindings. But the *security-relevant decisions* it makes —
//! "is this partition allowed to map to this release?" and "is this channel's
//! new frontier a rollback below the recorded floor?" — are pure functions of
//! already-fetched, already-signature-verified data. This module factors those
//! decisions out so they compile and are unit-tested on the native host,
//! exactly mirroring the native hub indexer
//! ([`aos_registry_hub`]'s `resolve_channels` / `enforce_floors`). The wasm
//! indexer is then a thin shell: fetch + verify signatures, call into here for
//! the accept/reject decision, then write D1.
//!
//! Keeping these here (free of any `worker` types) is what lets the native test
//! suite prove the Worker's channel verification is byte-for-byte the native
//! hub's, so the "exact fail-closed verifier" claim holds on the channel path
//! and not only the release path.

use anyhow::{bail, Result};

use aos_registry_surface::tag::SignedTag;
use aos_registry_surface::tagobject::TagTarget;

/// Resolve one already-verified channel partition to its release semver, with
/// the native indexer's two hard checks.
///
/// `signed` is the partition's signature-and-name-verified [`SignedTag`];
/// `releases` maps a verified release **tag object oid** (hex) to its semver
/// (the same `tag_to_semver` the native `resolve_channels` builds). The caller
/// has already run [`aos_registry_surface::tag::verify_signed_tag`] on the
/// payload, so this function only enforces the *target* invariants the native
/// hub enforces, which the Worker previously skipped:
///
/// 1. the partition must point at a **tag object** (`target_type == Tag`); a
///    partition that targets a commit, tree, or blob is a forged frontier;
/// 2. the targeted tag oid must be a **known, verified release**; an unknown
///    target is a forged or dangling pointer.
///
/// Returns the resolved release semver on success.
///
/// # Errors
///
/// Returns an error (failing the index for the registry, never silently
/// skipping) when the partition does not target a tag object, or targets a tag
/// oid absent from `releases`. This is the fail-closed behavior the native
/// `resolve_channels` already has; the Worker must not be weaker.
pub fn resolve_partition_release<'a>(
    path: &str,
    signed: &SignedTag,
    releases: &'a std::collections::BTreeMap<String, String>,
) -> Result<&'a String> {
    if signed.tag.target_type != TagTarget::Tag {
        bail!("partition {path} does not target a tag object");
    }
    match releases.get(&signed.tag.object) {
        Some(semver) => Ok(semver),
        None => bail!(
            "partition {path} targets unknown tag object {}",
            signed.tag.object
        ),
    }
}

/// Fold one resolved partition semver into the running channel frontier.
///
/// The frontier is the highest semver mapped on the channel (mirrors the
/// native `resolve_channels`). A `release` that does not parse as semver leaves
/// the frontier unchanged; the first parseable release seeds it.
pub fn advance_frontier(frontier: &mut Option<semver::Version>, release: &str) {
    if let Ok(version) = semver::Version::parse(release) {
        if frontier.as_ref().is_none_or(|f| version > *f) {
            *frontier = Some(version);
        }
    }
}

/// The anti-rollback decision for a channel about to be written.
///
/// Mirrors the native `enforce_floors`: given a channel's newly observed
/// `frontier` and its recorded `floor` (the highest frontier ever indexed for
/// this `registry_id`/channel), decide whether the new index is a rollback that
/// must be rejected. A missing floor (never indexed) or a frontier/floor that
/// does not parse as semver is permissive (cannot prove a rollback), exactly as
/// the native hub treats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorDecision {
    /// The new frontier is at or above the floor (or no comparison was
    /// possible): the channel may be written.
    Accept,
    /// The new frontier fell strictly below the recorded floor: reject the
    /// channel as a rollback (fail closed).
    Rollback,
}

/// Decide whether a channel's new `frontier` is a rollback below its `floor`.
///
/// `frontier` is the channel's newly observed frontier (`None` if the channel
/// mapped no parseable release this run); `floor` is the recorded anti-rollback
/// floor (`None` if the channel was never indexed). Returns
/// [`FloorDecision::Rollback`] only when both parse as semver and the new
/// frontier is strictly below the floor — matching the native
/// `enforce_floors`.
#[must_use]
pub fn floor_decision(frontier: Option<&str>, floor: Option<&str>) -> FloorDecision {
    let (Some(frontier), Some(floor)) = (frontier, floor) else {
        return FloorDecision::Accept;
    };
    let (Ok(frontier_v), Ok(floor_v)) = (
        semver::Version::parse(frontier),
        semver::Version::parse(floor),
    ) else {
        return FloorDecision::Accept;
    };
    if frontier_v < floor_v {
        FloorDecision::Rollback
    } else {
        FloorDecision::Accept
    }
}

/// Decide whether a channel's `floor` should be raised to its new `frontier`.
///
/// Mirrors the native `raise_floors`: the floor only ever *increases*. Returns
/// `true` when there is a parseable frontier and either no floor is recorded or
/// the new frontier is strictly greater than the recorded floor.
#[must_use]
pub fn should_raise_floor(frontier: &str, floor: Option<&str>) -> bool {
    if semver::Version::parse(frontier).is_err() {
        return false;
    }
    match floor {
        None => true,
        Some(floor) => match (
            semver::Version::parse(frontier),
            semver::Version::parse(floor),
        ) {
            (Ok(frontier_v), Ok(floor_v)) => frontier_v > floor_v,
            _ => false,
        },
    }
}

/// Whether an href is safe to emit as a link target.
///
/// Mirrors the native hub's `pages.rs` homepage policy: only `http`/`https`
/// URLs become links; anything else (`javascript:`, `data:`, …) must be
/// rendered as escaped plain text so a stored hostile URL cannot become an
/// active sink in the no-JS browse UI.
#[must_use]
pub fn is_safe_href(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::tagobject::{TagObject, TagTarget};

    fn signed_targeting(target_type: TagTarget, object: &str) -> SignedTag {
        SignedTag {
            tag: TagObject {
                object: object.to_string(),
                target_type,
                name: "stable".to_string(),
                tagger_when: None,
            },
            signed_payload: Vec::new(),
            signature: String::new(),
        }
    }

    fn releases() -> std::collections::BTreeMap<String, String> {
        let mut m = std::collections::BTreeMap::new();
        m.insert("tagoid1".to_string(), "1.2.0".to_string());
        m
    }

    #[test]
    fn partition_resolves_to_known_tag() {
        let signed = signed_targeting(TagTarget::Tag, "tagoid1");
        let releases = releases();
        let release = resolve_partition_release("channels/stable/00", &signed, &releases).unwrap();
        assert_eq!(release, "1.2.0");
    }

    #[test]
    fn partition_targeting_non_tag_is_rejected() {
        // A partition pointing straight at a commit (not a release tag object)
        // is a forged frontier: the native hub bails, so the Worker must too.
        let signed = signed_targeting(TagTarget::Commit, "tagoid1");
        let err = resolve_partition_release("channels/stable/00", &signed, &releases())
            .expect_err("non-tag target must be rejected");
        assert!(err.to_string().contains("does not target a tag object"));
    }

    #[test]
    fn partition_targeting_unknown_tag_is_rejected() {
        // An unknown/forged tag oid must HARD-fail, not be silently skipped.
        let signed = signed_targeting(TagTarget::Tag, "forged-oid");
        let err = resolve_partition_release("channels/stable/01", &signed, &releases())
            .expect_err("unknown target must be rejected");
        assert!(err.to_string().contains("unknown tag object"));
    }

    #[test]
    fn frontier_tracks_the_highest_semver() {
        let mut frontier = None;
        advance_frontier(&mut frontier, "1.0.0");
        advance_frontier(&mut frontier, "2.0.0");
        advance_frontier(&mut frontier, "1.5.0");
        advance_frontier(&mut frontier, "not-a-semver");
        assert_eq!(frontier.map(|v| v.to_string()), Some("2.0.0".to_string()));
    }

    #[test]
    fn floor_rejects_a_rollback() {
        assert_eq!(
            floor_decision(Some("1.0.0"), Some("2.0.0")),
            FloorDecision::Rollback
        );
    }

    #[test]
    fn floor_accepts_equal_or_higher_and_missing() {
        assert_eq!(
            floor_decision(Some("2.0.0"), Some("2.0.0")),
            FloorDecision::Accept
        );
        assert_eq!(
            floor_decision(Some("3.0.0"), Some("2.0.0")),
            FloorDecision::Accept
        );
        assert_eq!(floor_decision(Some("1.0.0"), None), FloorDecision::Accept);
        assert_eq!(floor_decision(None, Some("2.0.0")), FloorDecision::Accept);
    }

    #[test]
    fn floor_unparseable_is_permissive() {
        assert_eq!(
            floor_decision(Some("garbage"), Some("2.0.0")),
            FloorDecision::Accept
        );
    }

    #[test]
    fn raise_only_increases() {
        assert!(should_raise_floor("2.0.0", None));
        assert!(should_raise_floor("2.0.0", Some("1.0.0")));
        assert!(!should_raise_floor("1.0.0", Some("2.0.0")));
        assert!(!should_raise_floor("2.0.0", Some("2.0.0")));
        assert!(!should_raise_floor("not-semver", None));
    }

    #[test]
    fn safe_href_rejects_active_schemes() {
        assert!(is_safe_href("https://curl.se"));
        assert!(is_safe_href("http://example.com"));
        assert!(!is_safe_href("javascript:alert(1)"));
        assert!(!is_safe_href("data:text/html,<script>"));
        assert!(!is_safe_href("ftp://example.com"));
    }
}
