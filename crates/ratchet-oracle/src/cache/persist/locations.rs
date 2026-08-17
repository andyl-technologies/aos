//! Multi-location persistent-cache access with latency classes (MEMO-2).
//!
//! RFC-0007 doc 29 §5.4 generalizes the single `AOS_NIX_CACHE` root into an
//! **ordered list of disk locations, each with a latency class**. Every
//! location is a complete, self-contained persist-cache layout (schema,
//! `.locks/`, sidecar indexes, packs) — the existing machinery instantiated N
//! times, not a new on-disk format. Reads probe the primary first and then
//! each secondary from fastest to slowest class; a hit at a slower location
//! is *promoted* by copying the record into the primary so the next probe
//! answers from the fast path. Writes always target the primary; secondaries
//! are read-side capacity that is safe to lose (the cache is advisory end to
//! end, so a deleted or unreadable location is a miss, never an error).
//!
//! The secondary-location list is configured through the `AOS_NIX_MEMO_DISK`
//! knob, whose value is a comma-separated list of class-prefixed roots:
//!
//! ```text
//! AOS_NIX_MEMO_DISK=ssd:/fast/aos-cache-warm,hdd:/bulk/aos-cache-cold
//! ```
//!
//! Classes are `nvme`, `ssd`, and `hdd`; the primary `AOS_NIX_CACHE` root is
//! implicitly class `nvme`. Probe order sorts secondaries by class (fastest
//! first) and preserves declared order within a class.

use super::*;

/// The latency class of one persist-cache disk location.
///
/// Classes order probe priority only; they carry no semantic difference. A
/// record is equally valid at any location (doc 29 §5.6's invariant), so the
/// class exclusively trades lookup latency against capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PersistLatencyClass {
    /// Fastest class; the implicit class of the primary location.
    Nvme,
    /// Middle class.
    Ssd,
    /// Slowest class; bulk/cold storage.
    Hdd,
}

impl PersistLatencyClass {
    /// Returns the knob spelling of this class (`nvme`/`ssd`/`hdd`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nvme => "nvme",
            Self::Ssd => "ssd",
            Self::Hdd => "hdd",
        }
    }

    /// Parses a knob spelling, case-insensitively.
    fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "nvme" => Some(Self::Nvme),
            "ssd" => Some(Self::Ssd),
            "hdd" => Some(Self::Hdd),
            _ => None,
        }
    }
}

impl std::fmt::Display for PersistLatencyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One configured secondary disk location: a latency class plus a cache root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistDiskLocation {
    class: PersistLatencyClass,
    root: PathBuf,
}

impl PersistDiskLocation {
    /// Creates a disk-location spec from its class and cache root.
    pub fn new(class: PersistLatencyClass, root: impl Into<PathBuf>) -> Self {
        Self {
            class,
            root: root.into(),
        }
    }

    /// Returns this location's latency class.
    pub const fn class(&self) -> PersistLatencyClass {
        self.class
    }

    /// Returns this location's cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Parses an `AOS_NIX_MEMO_DISK`-shaped location list.
    ///
    /// The grammar is `class:path[,class:path...]` with classes `nvme`, `ssd`,
    /// and `hdd`. Empty segments are ignored so trailing commas are harmless.
    /// The returned list is sorted fastest class first, preserving declared
    /// order within a class (the probe order of §5.4).
    ///
    /// # Errors
    ///
    /// Returns [`PersistDiskLocationSpecError`] when a segment has no `:`
    /// separator, names an unknown class, or has an empty path. Callers treat
    /// a parse error as "feature off with a warning" — the store is advisory,
    /// so configuration mistakes must never fail evaluation.
    pub fn parse_list(spec: &str) -> Result<Vec<Self>, PersistDiskLocationSpecError> {
        let mut locations = Vec::new();
        for segment in spec.split(',') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let Some((class_token, path)) = segment.split_once(':') else {
                return Err(PersistDiskLocationSpecError::MissingSeparator {
                    segment: segment.to_string(),
                });
            };
            let Some(class) = PersistLatencyClass::parse(class_token) else {
                return Err(PersistDiskLocationSpecError::UnknownClass {
                    class: class_token.trim().to_string(),
                });
            };
            let path = path.trim();
            if path.is_empty() {
                return Err(PersistDiskLocationSpecError::EmptyPath {
                    segment: segment.to_string(),
                });
            }
            locations.push(Self::new(class, path));
        }
        locations.sort_by_key(|location| location.class);
        Ok(locations)
    }
}

/// An `AOS_NIX_MEMO_DISK` location list failed to parse.
#[derive(Debug, Error)]
pub enum PersistDiskLocationSpecError {
    /// A list segment carried no `class:path` separator.
    #[error("disk location segment {segment:?} has no `class:path` separator")]
    MissingSeparator {
        /// The offending segment.
        segment: String,
    },
    /// A list segment named a class outside `nvme`/`ssd`/`hdd`.
    #[error("unknown disk location class {class:?} (expected nvme, ssd, or hdd)")]
    UnknownClass {
        /// The unrecognized class token.
        class: String,
    },
    /// A list segment carried an empty path.
    #[error("disk location segment {segment:?} has an empty path")]
    EmptyPath {
        /// The offending segment.
        segment: String,
    },
}

/// Where a multi-location probe found its record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistLocationHit {
    /// The primary `AOS_NIX_CACHE` location answered.
    Primary,
    /// A secondary location of the given class answered.
    Secondary(PersistLatencyClass),
}

/// An opened ordered stack of persist-cache locations.
///
/// The primary is always present and always probed first; secondaries are
/// opened best-effort (an unopenable location is skipped with a debug log,
/// never an error — a lost location is a miss by design) and probed fastest
/// class first.
#[derive(Clone, Debug)]
pub struct PersistCacheLocations {
    primary: PersistCache,
    secondaries: Vec<(PersistLatencyClass, PersistCache)>,
}

impl PersistCacheLocations {
    /// Opens the primary root plus every openable secondary location.
    ///
    /// `verify` applies the primary's `AOS_NIX_CACHE_VERIFY` defensive decode
    /// setting to every opened location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] only when the *primary* root cannot be opened;
    /// secondary open failures are logged at debug level and the location is
    /// skipped.
    pub fn open(
        primary_root: impl Into<PathBuf>,
        verify: bool,
        secondaries: &[PersistDiskLocation],
    ) -> Result<Self, PersistError> {
        let primary = PersistCache::open(primary_root)?.with_value_decode_verification(verify);
        Ok(Self {
            primary,
            secondaries: open_secondary_caches(secondaries, verify),
        })
    }

    /// Wraps an already-opened primary with opened secondary locations.
    pub fn with_primary(
        primary: PersistCache,
        secondaries: Vec<(PersistLatencyClass, PersistCache)>,
    ) -> Self {
        Self {
            primary,
            secondaries,
        }
    }

    /// Returns the always-present primary location.
    pub const fn primary(&self) -> &PersistCache {
        &self.primary
    }

    /// Returns the opened secondary locations in probe order.
    pub fn secondaries(&self) -> &[(PersistLatencyClass, PersistCache)] {
        &self.secondaries
    }

    /// Returns whether any secondary location opened.
    pub fn has_secondaries(&self) -> bool {
        !self.secondaries.is_empty()
    }

    /// Iterates every opened location in probe order (primary first).
    pub fn iter(&self) -> impl Iterator<Item = (PersistLocationHit, &PersistCache)> {
        std::iter::once((PersistLocationHit::Primary, &self.primary)).chain(
            self.secondaries
                .iter()
                .map(|(class, cache)| (PersistLocationHit::Secondary(*class), cache)),
        )
    }

    /// Probes every location in order for a durable root-instantiation record.
    ///
    /// Location-level failures (index read errors, missing blobs) are logged
    /// and treated as a miss at that location; the probe continues to the next
    /// one. Returns the first hydrated record together with where it was
    /// found. The caller is responsible for revalidating the record's
    /// impure-input trace — a multi-location hit carries exactly the same
    /// trust as a primary hit, namely none until revalidated.
    pub fn load_root_instantiation(
        &self,
        key: PersistRootRecordKey,
    ) -> Option<(HydratedRootInstantiation, PersistLocationHit)> {
        if let Some(record) = load_root_instantiation_from(&self.primary, key, "primary") {
            return Some((record, PersistLocationHit::Primary));
        }
        for (class, cache) in &self.secondaries {
            if let Some(record) = load_root_instantiation_from(cache, key, class.as_str()) {
                return Some((record, PersistLocationHit::Secondary(*class)));
            }
        }
        None
    }

    /// Copies a record hydrated from a slower location into the primary.
    ///
    /// Promotion is a plain store through the primary's normal write path:
    /// closure blobs dedup through the content-addressed pack, and the
    /// record's original bookkeeping run id is preserved. Returns whether the
    /// promotion succeeded; failures are logged at debug level (the record
    /// remains readable from its home location either way).
    pub fn promote_root_instantiation(
        &self,
        key: PersistRootRecordKey,
        record: &HydratedRootInstantiation,
    ) -> bool {
        let root_bytes = record.root().as_os_str().as_bytes();
        match self.primary.store_root_instantiation(
            key,
            root_bytes,
            record.closure(),
            record.inputs(),
            record.run_id(),
        ) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(
                    target: "aos_nix::cache",
                    error = %error,
                    "root-record promotion into the primary location failed"
                );
                false
            }
        }
    }

    /// Demotes cold primary root records to the next slower latency class under
    /// size pressure (doc 29 §5.4/§5.6).
    ///
    /// Demotion is the mirror of [`Self::promote_root_instantiation`]: it plans
    /// on the primary (measure resident bytes, enumerate root records, select
    /// the largest and coldest victims for the policy's `bytes_to_free`), then
    /// moves each victim to the fastest opened secondary — always a class slower
    /// than the primary — and unroots it from the primary. A demoted record is
    /// not lost: its next probe hits the secondary and re-promotes upward.
    ///
    /// The move is a sequence of **single-location-locked steps**, never holding
    /// two locations' locks at once, so the two-location operation cannot form a
    /// cross-location lock cycle: (a) read the record from the primary, (b) copy
    /// it down under the secondary's own write path, (c) verify it is durable at
    /// the secondary, and only then (d) unroot it from the primary under the
    /// primary's exclusive root-record lock. A crash between (c) and (d) leaves
    /// the record rooted in both locations — a benign duplicate, since lookups
    /// probe primary-then-secondary and either answers correctly.
    ///
    /// Demotion is advisory: a per-victim copy-down or verify failure is logged
    /// and drops that victim from the moved set, never failing the sweep. When
    /// no secondary is opened the sweep is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PersistDemotionError`] only when primary planning or the final
    /// primary unroot fails; per-victim secondary failures are swallowed.
    pub fn demote_under_size_pressure(
        &self,
        policy: PersistStorageMaintenancePolicy,
    ) -> Result<PersistDemotionOutcome, PersistDemotionError> {
        let plan = self.primary.plan_demotion(policy)?;
        if plan.victims().is_empty() {
            let reason = if plan.bytes_to_free() == 0 {
                PersistDemotionSkip::NoSizePressure
            } else {
                PersistDemotionSkip::NoCandidates
            };
            return Ok(PersistDemotionOutcome::Skipped { reason });
        }
        // Demotion writes process-family-keyed records, so it may only target a
        // secondary recorded under the same content-hash family; writing them
        // into a foreign-family secondary would leave records unfindable there
        // (the families domain-separate their keys). Pick the fastest
        // same-family secondary (RFC-0007 §P4 Option C).
        let primary_family = self.primary.hash_family();
        let Some((target_class, secondary)) = self
            .secondaries
            .iter()
            .find(|(_, secondary)| secondary.hash_family() == primary_family)
        else {
            return Ok(PersistDemotionOutcome::Skipped {
                reason: PersistDemotionSkip::NoSecondaryLocation,
            });
        };

        let mut demoted_keys = Vec::new();
        let mut estimated_bytes_freed = 0u64;
        for victim in plan.victims() {
            let key = victim.key();
            let record = match self.primary.load_root_instantiation(key) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(error) => {
                    tracing::debug!(
                        target: "aos_nix::cache",
                        error = %error,
                        "demotion could not load a victim from the primary; skipping it"
                    );
                    continue;
                }
            };
            let root_bytes = record.root().as_os_str().as_bytes();
            if let Err(error) = secondary.store_root_instantiation(
                key,
                root_bytes,
                record.closure(),
                record.inputs(),
                record.run_id(),
            ) {
                tracing::debug!(
                    target: "aos_nix::cache",
                    error = %error,
                    class = %target_class,
                    "demotion copy-down to a secondary failed; keeping the primary root"
                );
                continue;
            }
            // Never unroot from the primary until the down-copy is durable.
            match secondary.load_root_instantiation(key) {
                Ok(Some(_)) => {}
                _ => {
                    tracing::debug!(
                        target: "aos_nix::cache",
                        class = %target_class,
                        "demoted record did not verify at the secondary; keeping the primary root"
                    );
                    continue;
                }
            }
            demoted_keys.push(key);
            estimated_bytes_freed = estimated_bytes_freed.saturating_add(victim.resident_bytes());
        }

        if demoted_keys.is_empty() {
            return Ok(PersistDemotionOutcome::Skipped {
                reason: PersistDemotionSkip::NoCandidates,
            });
        }
        let key_set: std::collections::BTreeSet<_> = demoted_keys.iter().copied().collect();
        self.primary.unroot_root_records(&key_set)?;
        Ok(PersistDemotionOutcome::Demoted {
            demoted_keys,
            estimated_bytes_freed,
            target_class: *target_class,
        })
    }
}

/// Opens every openable secondary location in probe order.
///
/// Locations that fail to open are skipped with a debug log: a secondary is
/// additive, safe-to-lose capacity, so its absence must never surface as an
/// error (doc 29 §5.4).
pub fn open_secondary_caches(
    locations: &[PersistDiskLocation],
    verify: bool,
) -> Vec<(PersistLatencyClass, PersistCache)> {
    let mut caches = Vec::new();
    for location in locations {
        match PersistCache::open_secondary(location.root()) {
            Ok(cache) => {
                caches.push((
                    location.class(),
                    cache.with_value_decode_verification(verify),
                ));
            }
            Err(error) => {
                tracing::debug!(
                    target: "aos_nix::cache",
                    root = %location.root().display(),
                    class = %location.class(),
                    error = %error,
                    "secondary persist-cache location failed to open; skipping it"
                );
            }
        }
    }
    caches
}

/// Loads a root record from one location, mapping every failure to a miss.
fn load_root_instantiation_from(
    cache: &PersistCache,
    key: PersistRootRecordKey,
    location_label: &str,
) -> Option<HydratedRootInstantiation> {
    match cache.load_root_instantiation(key) {
        Ok(record) => record,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                location = location_label,
                error = %error,
                "root-record load failed at a cache location; treating it as a miss"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_orders_fastest_class_first() {
        let locations =
            PersistDiskLocation::parse_list("hdd:/cold,nvme:/fast,ssd:/warm").expect("spec parses");
        assert_eq!(
            locations,
            vec![
                PersistDiskLocation::new(PersistLatencyClass::Nvme, "/fast"),
                PersistDiskLocation::new(PersistLatencyClass::Ssd, "/warm"),
                PersistDiskLocation::new(PersistLatencyClass::Hdd, "/cold"),
            ]
        );
    }

    #[test]
    fn parse_list_preserves_declared_order_within_a_class() {
        let locations = PersistDiskLocation::parse_list("hdd:/one,hdd:/two").expect("spec parses");
        assert_eq!(locations[0].root(), Path::new("/one"));
        assert_eq!(locations[1].root(), Path::new("/two"));
    }

    #[test]
    fn parse_list_ignores_empty_segments() {
        let locations = PersistDiskLocation::parse_list(" ,hdd:/cold, ").expect("spec parses");
        assert_eq!(locations.len(), 1);
    }

    #[test]
    fn parse_list_rejects_unknown_class_and_missing_parts() {
        assert!(matches!(
            PersistDiskLocation::parse_list("tape:/cold"),
            Err(PersistDiskLocationSpecError::UnknownClass { .. })
        ));
        assert!(matches!(
            PersistDiskLocation::parse_list("/cold"),
            Err(PersistDiskLocationSpecError::MissingSeparator { .. })
        ));
        assert!(matches!(
            PersistDiskLocation::parse_list("hdd:"),
            Err(PersistDiskLocationSpecError::EmptyPath { .. })
        ));
    }
}
