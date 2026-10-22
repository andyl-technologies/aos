//! Channel and rollout selection helpers.
//!
//! A registry channel (e.g. `stable`) is published as a set of
//! [`PARTITION_COUNT`] static partition objects under
//! `channels/<channel>/<bucket-hex>`, each pointing at a signed release tag.
//! Every host deterministically hashes itself into one bucket (from a
//! registry-local salt generated on first sync), so producers can advance a
//! release across partitions gradually and hosts follow the rollout without
//! any server-side coordination.
//!
//! Two safety properties are enforced here:
//!
//! - **Monotonic floor**: [`check_floor`] refuses releases older than the
//!   highest release a host has already verified and installed, blocking
//!   rollback attacks against the mutable channel pointer.
//! - **Complete partition sets**: [`assert_full_partition_set`] refuses to
//!   publish a channel with unassigned buckets, so every consumer always
//!   resolves to some release.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::future::Future;

use crate::tagobject::{TagObject, TagTarget, parse_tag_object, verify_name_binding};

/// An unsigned channel partition tag ready for a caller's signing adapter.
///
/// Rendering is independent of key custody, Git repositories, and transports.
/// The tagger and message are preserved byte-for-byte; callers provide the
/// complete Git tagger header value, including timestamp and timezone.
#[derive(Debug, Clone)]
pub struct PartitionTag {
    payload: Vec<u8>,
}

impl PartitionTag {
    /// Renders a channel-bound tag pointing at an exact release tag object.
    ///
    /// The message receives the final newline Git includes before its appended
    /// SSH signature. The tagger is the full value after `tagger `.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe channel name, a nonexact SHA-1 or SHA-256
    /// object id, an empty or multiline tagger, or a message containing signature
    /// armor that could be confused with the appended signature.
    pub fn new(
        channel: &str,
        release_tag_object: &str,
        tagger: &str,
        message: &str,
    ) -> Result<Self> {
        validate_channel_name(channel)?;
        validate_release_tag_object(release_tag_object)?;
        if tagger.is_empty() || tagger.chars().any(char::is_control) {
            bail!("channel partition tagger must be a nonempty single header value");
        }
        if message.contains("-----BEGIN SSH SIGNATURE-----") {
            bail!("channel partition message cannot contain SSH signature armor");
        }

        let payload = format!(
            "object {release_tag_object}\ntype tag\ntag {channel}\ntagger {tagger}\n\n{message}\n"
        )
        .into_bytes();
        Ok(Self { payload })
    }

    /// Returns the exact bytes a Git-context signer must authorize.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Signs the partition through a synchronous key-custody adapter.
    ///
    /// The adapter signs the supplied bytes in SSHSIG's `git` namespace and
    /// returns the complete armored signature, including any trailing newline.
    /// It owns key authorization and signature verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing adapter fails.
    pub fn sign_with(self, signer: impl FnOnce(&[u8]) -> Result<String>) -> Result<Vec<u8>> {
        let signature = signer(&self.payload)?;
        Ok(self.attach_signature(&signature))
    }

    /// Signs the partition through an asynchronous key-custody adapter.
    ///
    /// The adapter receives owned payload bytes so external providers can
    /// authorize a request across an await point. It signs in the `git`
    /// namespace, verifies its response, and preserves signature whitespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing adapter fails.
    pub async fn sign_with_async<F, Fut>(self, signer: F) -> Result<Vec<u8>>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<String>>,
    {
        let signature = signer(self.payload.clone()).await?;
        Ok(self.attach_signature(&signature))
    }

    fn attach_signature(mut self, signature: &str) -> Vec<u8> {
        self.payload.extend_from_slice(signature.as_bytes());
        self.payload
    }
}

/// Validates a rollout channel as one safe Git reference and path segment.
///
/// # Errors
///
/// Returns an error for empty, reserved, unsafe, or multisegment channel names.
pub fn validate_channel_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("invalid channel name: must not be empty");
    }
    if name == "@"
        || name == "HEAD"
        || name.starts_with('-')
        || name.starts_with('/')
        || name.ends_with('/')
        || name.ends_with('.')
        || name.starts_with("refs/")
        || name.contains("..")
        || name.contains("@{")
        || name.contains("//")
    {
        bail!("invalid channel name '{name}': use a safe Git ref shorthand");
    }
    if name.contains('/') {
        bail!("invalid channel name '{name}': use a single safe Git ref segment");
    }
    if name.starts_with('.') || name.ends_with(".lock") {
        bail!("invalid channel name '{name}': use safe Git ref components");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!(
            "invalid channel name '{name}': use only ASCII letters, digits, '.', '_', '-', and '/'"
        );
    }
    Ok(())
}

/// Parses a partition's channel binding and exact release tag target.
///
/// This validates tag headers. Consumers additionally verify the signature
/// against their registry trust set with [`crate::tag::verify_signed_tag`].
///
/// # Errors
///
/// Returns an error for invalid UTF-8, malformed headers, a different channel,
/// a non-tag or nonexact object target, or a target differing from
/// `expected_release_tag`.
pub fn parse_partition_target(
    payload: &[u8],
    channel: &str,
    expected_release_tag: Option<&str>,
) -> Result<TagObject> {
    let text = std::str::from_utf8(payload).context("channel partition is not UTF-8")?;
    let tag = parse_tag_object(text)?;
    verify_name_binding(&tag, channel)?;
    validate_release_tag_object(&tag.object)?;
    if tag.target_type != TagTarget::Tag
        || expected_release_tag.is_some_and(|expected| tag.object != expected)
    {
        bail!("channel partition does not target the release tag object");
    }
    Ok(tag)
}

fn validate_release_tag_object(object: &str) -> Result<()> {
    if !matches!(object.len(), 40 | 64) || !object.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("channel partition requires an exact release tag object id");
    }
    Ok(())
}

/// Returns the successor of a channel operation generation.
///
/// # Errors
///
/// Returns an error when the generation counter is exhausted.
pub fn next_generation(prior: u64) -> Result<u64> {
    prior
        .checked_add(1)
        .context("channel generation overflowed")
}

/// Validates an inclusive partition range before channel mutation.
///
/// # Errors
///
/// Returns an error when either bound exceeds 255 or the range is reversed.
pub fn partition_range(first: u16, last: u16) -> Result<Vec<u8>> {
    if first > last || last >= PARTITION_COUNT as u16 {
        bail!("channel partition range must be ordered within 0..255");
    }
    (first..=last)
        .map(|bucket| u8::try_from(bucket).context("channel partition bucket exceeds 255"))
        .collect()
}

/// The number of rollout partitions in every channel.
pub const PARTITION_COUNT: usize = 256;

/// In-memory view of the 256 partition targets for one channel.
///
/// Each bucket optionally targets one release version; `None` means the
/// bucket has not been assigned yet (only valid before first publication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMap {
    targets: Vec<Option<semver::Version>>,
}

impl Default for PartitionMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionMap {
    /// Creates an empty partition map with every bucket unassigned.
    pub fn new() -> Self {
        Self {
            targets: vec![None; PARTITION_COUNT],
        }
    }

    /// Creates a partition map with every bucket pointing at `version`.
    pub fn all(version: semver::Version) -> Self {
        Self {
            targets: vec![Some(version); PARTITION_COUNT],
        }
    }

    /// Sets a partition target.
    ///
    /// # Errors
    ///
    /// Returns an error if `bucket` is outside the fixed partition range.
    pub fn set(&mut self, bucket: usize, version: semver::Version) -> Result<()> {
        let slot = self
            .targets
            .get_mut(bucket)
            .ok_or_else(|| anyhow::anyhow!("partition bucket {bucket} is outside 0..255"))?;
        *slot = Some(version);
        Ok(())
    }

    /// Returns the target release for a bucket, or `None` if unassigned.
    pub fn get(&self, bucket: u8) -> Option<&semver::Version> {
        self.targets[bucket as usize].as_ref()
    }

    /// Iterates over all partition targets in bucket order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, Option<&semver::Version>)> {
        self.targets
            .iter()
            .enumerate()
            .map(|(i, v)| (i as u8, v.as_ref()))
    }

    /// Counts partitions that target `version`.
    pub fn count_targeting(&self, version: &semver::Version) -> usize {
        self.targets
            .iter()
            .filter(|target| target.as_ref() == Some(version))
            .count()
    }
}

/// Compute the stable rollout bucket for a seed string.
///
/// The bucket is the low byte of `sha256(seed)`, yielding `0..=255`.
pub fn select_bucket(seed: &str) -> u8 {
    let digest = Sha256::digest(seed.as_bytes());
    digest[31]
}

/// Compute a bucket from a registry-local salt.
///
/// The salt is generated on first channel sync and the resulting bucket index is
/// persisted, so cloned images do not inherit an image-baked machine id and the
/// host keeps the same rollout assignment after the first successful sync.
pub fn select_registry_bucket(registry: &str, salt: &str) -> u8 {
    select_bucket(&format!("{registry}\0{salt}"))
}

/// Render a bucket as a two-digit lowercase hex partition name.
pub fn bucket_hex(bucket: u8) -> String {
    format!("{bucket:02x}")
}

/// Return the static partition object path for a channel and bucket.
///
/// Bucket `10` of channel `stable` maps to `channels/stable/0a`.
pub fn partition_path(channel: &str, bucket: u8) -> String {
    format!("channels/{channel}/{}", bucket_hex(bucket))
}

/// Return the deterministic probe-forward order for a bucket.
///
/// Starts at the host's own bucket and wraps around all 256 buckets, so a
/// consumer whose partition object is missing falls forward to the next
/// available one instead of failing.
pub fn probe_order(bucket: u8) -> Vec<u8> {
    (0..=255).map(|i| bucket.wrapping_add(i)).collect()
}

/// Use a persisted bucket when present, otherwise compute one from registry salt.
pub fn resolve_bucket(persisted: Option<u8>, registry: &str, salt: &str) -> u8 {
    persisted.unwrap_or_else(|| select_registry_bucket(registry, salt))
}

/// Refuse candidates older than the persisted semver floor.
///
/// Equal versions are accepted as a no-op; newer versions raise the floor after
/// the caller has verified and installed the target.
///
/// # Errors
///
/// Returns an error when `candidate` is strictly older than `floor`,
/// indicating an attempted channel rollback.
pub fn check_floor(floor: Option<&semver::Version>, candidate: &semver::Version) -> Result<()> {
    if let Some(floor) = floor {
        if candidate < floor {
            bail!(
                "registry rollback refused: target release {candidate} is older than floor {floor}",
            );
        }
    }
    Ok(())
}

/// Compute the frontier release for a partition map.
///
/// The frontier is the maximum semver targeted by any partition.
pub fn compute_frontier(map: &PartitionMap) -> Option<semver::Version> {
    map.targets.iter().filter_map(Clone::clone).max()
}

/// Refuse to publish a channel with missing partition targets.
///
/// # Errors
///
/// Returns an error listing the hex names of every unassigned partition.
pub fn assert_full_partition_set(map: &PartitionMap) -> Result<()> {
    let missing: Vec<String> = map
        .iter()
        .filter_map(|(bucket, target)| {
            if target.is_none() {
                Some(bucket_hex(bucket))
            } else {
                None
            }
        })
        .collect();

    if !missing.is_empty() {
        bail!(
            "channel partition set is incomplete; missing {} partition(s): {}",
            missing.len(),
            missing.join(", "),
        );
    }
    Ok(())
}

/// Select the next `count` partitions to advance to `target` in ascending order.
///
/// Partitions that already target `target` are skipped, so calling this
/// repeatedly walks the whole channel toward the new release.
pub fn ascending_fill(count: usize, current: &PartitionMap, target: &semver::Version) -> Vec<u8> {
    current
        .iter()
        .filter_map(|(bucket, version)| {
            if version == Some(target) {
                None
            } else {
                Some(bucket)
            }
        })
        .take(count)
        .collect()
}

/// Resolve which partitions a channel advance should touch: `--count`
/// picks the lowest-numbered partitions not yet on the target version
/// (ascending fill), while `--partitions` names buckets explicitly.
/// Exactly one of the two must be given.
///
/// # Errors
///
/// Returns an error for conflicting or missing selection modes, invalid bucket
/// lists, or a count greater than the channel partition count.
pub fn select_partitions_for_advance(
    count: Option<usize>,
    partitions: Option<&str>,
    map: &PartitionMap,
    version: &semver::Version,
) -> Result<Vec<u8>> {
    match (count, partitions) {
        (Some(_), Some(_)) => bail!("use only one of --count or --partitions"),
        (None, None) => bail!("one of --count or --partitions is required"),
        (Some(count), None) => {
            if count > PARTITION_COUNT {
                bail!("--count must be <= {}", PARTITION_COUNT);
            }
            Ok(ascending_fill(count, map, version))
        }
        (None, Some(spec)) => parse_partition_list(spec),
    }
}

/// Refuse producer-side channel rewrites that would lower any selected
/// partition's semver target.
///
/// # Errors
///
/// Returns an error when any selected bucket would target an older release.
pub fn ensure_channel_advance_fix_forward(
    map: &PartitionMap,
    selected: &[u8],
    version: &semver::Version,
) -> Result<()> {
    for bucket in selected {
        let Some(current) = map.get(*bucket) else {
            continue;
        };
        if version < current {
            bail!(
                "channel advance would decrement partition {} from {} to {}; publish a newer fix-forward release instead",
                bucket_hex(*bucket),
                current,
                version,
            );
        }
    }
    Ok(())
}

/// Parses a comma-separated decimal and hexadecimal partition selection.
///
/// Duplicate buckets retain their first position; empty comma fields are ignored.
///
/// # Errors
///
/// Returns an error when the selection is empty or a bucket is outside 0..255.
pub fn parse_partition_list(spec: &str) -> Result<Vec<u8>> {
    let mut buckets = Vec::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bucket = parse_partition(raw)?;
        if !buckets.contains(&bucket) {
            buckets.push(bucket);
        }
    }
    if buckets.is_empty() {
        bail!("partition list is empty");
    }
    Ok(buckets)
}

/// Parse a single partition bucket: `0x`-prefixed or letter-containing
/// strings are hex, everything else is decimal.
fn parse_partition(raw: &str) -> Result<u8> {
    if let Some(hex) = raw.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    if raw.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')) {
        return u8::from_str_radix(raw, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    raw.parse::<u8>()
        .with_context(|| format!("invalid decimal partition '{raw}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn partition_signing_adapters_preserve_payload_and_signature_bytes() {
        let oid = "ab".repeat(32);
        let tagger = "Registry Maintainer <registry@example.com> 1770000000 -0700";
        let message = "AOS channel stable partition 0a";
        let partition = PartitionTag::new("stable", &oid, tagger, message).unwrap();
        let expected =
            format!("object {oid}\ntype tag\ntag stable\ntagger {tagger}\n\n{message}\n");
        assert_eq!(partition.payload(), expected.as_bytes());

        let key = ed25519_dalek::SigningKey::from_bytes(&[27u8; 32]);
        let sign = |bytes: &[u8]| Ok(format!("{}\n", crate::sshsig::sign_armored(bytes, &key)));
        let signed = partition.clone().sign_with(sign).unwrap();
        let future = partition.sign_with_async(|bytes| std::future::ready(sign(&bytes)));
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let std::task::Poll::Ready(async_signed) = future.as_mut().poll(&mut context) else {
            panic!("ready signing adapter must complete immediately");
        };
        assert_eq!(async_signed.unwrap(), signed);

        let trust = crate::sshsig::trusted_key_line("aos-core", &key.verifying_key());
        let verified = crate::tag::verify_signed_tag(&signed, "stable", &[trust]).unwrap();
        assert_eq!(verified.signed_payload, expected.as_bytes());
        assert_eq!(verified.tag.object, oid);
    }

    #[test]
    fn partition_renderer_rejects_header_and_signature_confusion() {
        let oid = "ab".repeat(32);
        assert!(PartitionTag::new("../stable", &oid, "Maintainer 1 +0000", "partition").is_err());
        assert!(PartitionTag::new("stable", "HEAD", "Maintainer 1 +0000", "partition").is_err());
        assert!(PartitionTag::new("stable", &oid, "Maintainer\ntype commit", "partition").is_err());
        assert!(
            PartitionTag::new(
                "stable",
                &oid,
                "Maintainer 1 +0000",
                "-----BEGIN SSH SIGNATURE-----"
            )
            .is_err()
        );
    }

    #[test]
    fn partition_target_validation_rejects_replayed_channel_or_release() {
        let oid = "ab".repeat(32);
        let partition =
            PartitionTag::new("stable", &oid, "Maintainer 1 +0000", "partition").unwrap();
        parse_partition_target(partition.payload(), "stable", Some(&oid)).unwrap();
        assert!(parse_partition_target(partition.payload(), "candidate", Some(&oid)).is_err());
        assert!(
            parse_partition_target(partition.payload(), "stable", Some(&"cd".repeat(32))).is_err()
        );
        let commit = String::from_utf8(partition.payload().to_vec())
            .unwrap()
            .replace("type tag", "type commit");
        assert!(parse_partition_target(commit.as_bytes(), "stable", None).is_err());
    }

    #[test]
    fn generation_and_partition_range_validation_fail_before_mutation() {
        assert_eq!(next_generation(7).unwrap(), 8);
        assert!(next_generation(u64::MAX).is_err());
        assert_eq!(partition_range(254, 255).unwrap(), vec![254, 255]);
        assert_eq!(partition_range(0, 255).unwrap().len(), PARTITION_COUNT);
        assert!(partition_range(2, 1).is_err());
        assert!(partition_range(255, 256).is_err());
    }

    #[test]
    fn bucket_is_deterministic() {
        assert_eq!(select_bucket("seed-a"), select_bucket("seed-a"));
        assert_ne!(select_bucket("seed-a"), select_bucket("seed-b"));
    }

    #[test]
    fn registry_bucket_uses_registry_local_salt() {
        assert_eq!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("core", "salt-a"),
        );
        assert_ne!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("core", "salt-b"),
        );
        assert_ne!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("extras", "salt-a"),
        );
    }

    #[test]
    fn bucket_hex_two_digits() {
        assert_eq!(bucket_hex(0), "00");
        assert_eq!(bucket_hex(5), "05");
        assert_eq!(bucket_hex(255), "ff");
    }

    #[test]
    fn partition_path_uses_two_digit_bucket() {
        assert_eq!(partition_path("stable", 10), "channels/stable/0a");
    }

    #[test]
    fn probe_order_wraps_and_covers_all_buckets() {
        let order = probe_order(254);
        assert_eq!(order[0], 254);
        assert_eq!(order[1], 255);
        assert_eq!(order[2], 0);
        assert_eq!(order.len(), 256);
        let unique: HashSet<u8> = order.into_iter().collect();
        assert_eq!(unique.len(), 256);
    }

    #[test]
    fn persisted_bucket_wins() {
        assert_eq!(resolve_bucket(Some(42), "core", "new-salt"), 42);
    }

    #[test]
    fn persisted_bucket_survives_bucket_source_migration() {
        let migrated = resolve_bucket(Some(183), "core", "registry-local-salt");
        assert_eq!(migrated, 183);
    }

    #[test]
    fn floor_allows_equal_or_newer() {
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.2")).is_ok());
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.3")).is_ok());
    }

    #[test]
    fn floor_rejects_older() {
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.1")).is_err());
    }

    #[test]
    fn floor_allows_missing_floor() {
        assert!(check_floor(None, &v("0.1.0")).is_ok());
    }

    #[test]
    fn frontier_is_max_semver_over_partitions() {
        let mut map = PartitionMap::all(v("1.1.3"));
        map.set(0, v("1.2.0")).unwrap();
        map.set(255, v("1.0.0")).unwrap();

        assert_eq!(compute_frontier(&map), Some(v("1.2.0")));
    }

    #[test]
    fn full_partition_set_rejects_missing_targets() {
        let mut map = PartitionMap::all(v("1.0.0"));
        map.targets[7] = None;

        let err = assert_full_partition_set(&map).unwrap_err().to_string();
        assert!(err.contains("07"), "got: {err}");
    }

    #[test]
    fn full_partition_set_accepts_complete_map() {
        let map = PartitionMap::all(v("1.0.0"));
        assert_full_partition_set(&map).unwrap();
    }

    #[test]
    fn ascending_fill_skips_already_advanced_partitions() {
        let mut map = PartitionMap::all(v("1.0.0"));
        map.set(0, v("1.1.0")).unwrap();
        map.set(2, v("1.1.0")).unwrap();

        assert_eq!(ascending_fill(4, &map, &v("1.1.0")), vec![1, 3, 4, 5]);
    }
    #[test]
    fn partition_list_accepts_decimal_and_hex() {
        assert_eq!(
            parse_partition_list("0,1,0a,0xff,1").unwrap(),
            vec![0, 1, 10, 255],
        );
        assert!(parse_partition_list("").is_err());
        assert!(parse_partition_list("256").is_err());
    }

    #[test]
    fn channel_advance_selector_requires_one_mode() {
        let map = PartitionMap::all(semver::Version::parse("1.0.0").unwrap());
        let target = semver::Version::parse("1.1.0").unwrap();

        assert!(select_partitions_for_advance(None, None, &map, &target).is_err());
        assert!(select_partitions_for_advance(Some(1), Some("0"), &map, &target).is_err());
        assert_eq!(
            select_partitions_for_advance(Some(3), None, &map, &target).unwrap(),
            vec![0, 1, 2],
        );
    }

    #[test]
    fn channel_advance_rejects_selected_partition_decrement() {
        let mut map = PartitionMap::all(semver::Version::parse("1.1.0").unwrap());
        map.set(2, semver::Version::parse("1.0.0").unwrap())
            .unwrap();
        let older = semver::Version::parse("1.0.0").unwrap();
        let same = semver::Version::parse("1.1.0").unwrap();
        let newer = semver::Version::parse("1.2.0").unwrap();

        let err = ensure_channel_advance_fix_forward(&map, &[0], &older).unwrap_err();
        assert!(format!("{err:#}").contains("decrement partition 00 from 1.1.0 to 1.0.0"));
        ensure_channel_advance_fix_forward(&map, &[0], &same).unwrap();
        ensure_channel_advance_fix_forward(&map, &[0, 2], &newer).unwrap();
    }
}
