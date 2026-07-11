//! Packed, multi-location persistence for address-free tier-2 bodies.
//!
//! Compiled bodies share the evaluator's indexed `files/pack.blob` store and
//! probe the configured L2 locations in latency order, then the optional L3
//! network catalog. A verified secondary or network hit is promoted through
//! the primary's ordinary indexed-write path. Missing, unreadable, corrupt,
//! source-mismatched, or verifier-rejected records are advisory misses;
//! executable pages and process addresses are never stored.

use std::cell::Cell;
use std::path::Path;

use ratchet_core::{Ir, IrId};
use ratchet_jit::{
    ACTIVE_CRANELIFT_CODEGEN_VERSION, JitTier2ChainLowering, JitTier2LambdaLowering,
    compiled_body_target_triple, decode_tier2_chain_lowering, decode_tier2_lambda_lowering,
    encode_tier2_chain_lowering, encode_tier2_lambda_lowering,
};
use ratchet_oracle::cache::{
    CompiledBodyRecordHash, LoweredIrFingerprint, PersistBlobKey, PersistCache,
    PersistCacheLocations, PersistDiskLocation, PersistFileArtifactIndexEntry,
    PersistFileArtifactIndexValue, PersistFileArtifactKey, PersistFileBlobHash, PersistLocationHit,
    lowered_ir_fingerprint,
};
use ratchet_oracle::eval::tree_walk::{MemoNetMode, MemoNetOptions, TreeWalkOptions};

use super::NixJitTier1Engine;
use crate::native::memo_net;

mod stats;

use stats::CompiledBodyCacheStats;

const MAGIC: &[u8; 8] = b"AOSJIT2\0";
const SCHEMA_VERSION: u32 = 2;
const HEADER_LEN: usize = 68;
const CHAIN_MAGIC: &[u8; 8] = b"AOSJTC1\0";
const CHAIN_SCHEMA_VERSION: u32 = 1;
const CHAIN_HEADER_LEN: usize = 52;
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

pub(in crate::jit::engine) struct CompiledBodyCache {
    locations: PersistCacheLocations,
    net: Option<MemoNetOptions>,
    stats: Cell<CompiledBodyCacheStats>,
}

impl CompiledBodyCache {
    #[cfg(test)]
    fn open(
        persist_root: &Path,
        verify: bool,
        secondaries: &[PersistDiskLocation],
    ) -> Option<Self> {
        Self::open_with_net(persist_root, verify, secondaries, None)
    }

    fn open_with_net(
        persist_root: &Path,
        verify: bool,
        secondaries: &[PersistDiskLocation],
        net: Option<&MemoNetOptions>,
    ) -> Option<Self> {
        match PersistCacheLocations::open(persist_root, verify, secondaries) {
            Ok(locations) => Some(Self {
                locations,
                net: net.cloned(),
                stats: Cell::new(CompiledBodyCacheStats::default()),
            }),
            Err(error) => {
                tracing::debug!(
                    target: "aos_nix::cache",
                    root = %persist_root.display(),
                    error = %error,
                    "compiled-body primary cache location failed to open"
                );
                None
            }
        }
    }

    pub(super) fn load(
        &self,
        ir: &Ir,
        pattern: IrId,
        body: IrId,
        budget: i64,
    ) -> Option<JitTier2LambdaLowering> {
        let fingerprint = lowered_ir_fingerprint(ir).ok()?;
        let key = record_key(fingerprint, pattern, body, budget);
        self.load_record(key, |bytes| {
            read_record(bytes, fingerprint, pattern, body, budget)
        })
    }

    pub(super) fn store(
        &self,
        ir: &Ir,
        pattern: IrId,
        body: IrId,
        budget: i64,
        lowering: &JitTier2LambdaLowering,
    ) {
        let Some((key, record)) = encode_record(ir, pattern, body, budget, lowering) else {
            return;
        };
        self.store_record(key, &record, "compiled-body indexed write failed");
    }

    /// Loads and verifies one fused-chain lowering from the ordered L2 set.
    pub(in crate::jit::engine) fn load_chain(
        &self,
        ir: &Ir,
        semantic_identity: &[u8],
        source: IrId,
        arity: u32,
        self_upval: Option<(u32, u32)>,
        budget: i64,
    ) -> Option<JitTier2ChainLowering> {
        let fingerprint = lowered_ir_fingerprint(ir).ok()?;
        let record_hash = chain_record_hash(fingerprint, semantic_identity, budget);
        let key = PersistFileArtifactKey::for_compiled_body(record_hash);
        self.load_record(key, |bytes| {
            read_chain_record(bytes, record_hash, source, arity, self_upval)
        })
    }

    /// Stores one fused-chain lowering under its complete semantic identity.
    pub(in crate::jit::engine) fn store_chain(
        &self,
        ir: &Ir,
        semantic_identity: &[u8],
        budget: i64,
        lowering: &JitTier2ChainLowering,
    ) {
        let Ok(fingerprint) = lowered_ir_fingerprint(ir) else {
            return;
        };
        let record_hash = chain_record_hash(fingerprint, semantic_identity, budget);
        let Some(record) = encode_chain_record(record_hash, lowering) else {
            return;
        };
        let key = PersistFileArtifactKey::for_compiled_body(record_hash);
        self.store_record(
            key,
            &record,
            "fused-chain compiled-body indexed write failed",
        );
    }

    /// Returns the production cache-event snapshot for this engine.
    pub(in crate::jit::engine) fn stats(&self) -> CompiledBodyCacheStats {
        self.stats.get()
    }

    fn load_record<T>(
        &self,
        key: PersistFileArtifactKey,
        decode: impl Fn(&[u8]) -> Result<T, ReadRecordError>,
    ) -> Option<T> {
        self.update_stats(|stats| stats.lookups = stats.lookups.saturating_add(1));
        let mut saw_secondary = false;
        for (location, cache) in self.locations.iter() {
            saw_secondary |= location != PersistLocationHit::Primary;
            let Some(bytes) = read_indexed_record(cache, key, location) else {
                if location == PersistLocationHit::Primary {
                    self.update_stats(|stats| {
                        stats.primary_misses = stats.primary_misses.saturating_add(1);
                    });
                }
                continue;
            };
            let Ok(decoded) = decode(&bytes) else {
                self.update_stats(|stats| {
                    stats.validation_failures = stats.validation_failures.saturating_add(1);
                    if location == PersistLocationHit::Primary {
                        stats.primary_misses = stats.primary_misses.saturating_add(1);
                    }
                });
                continue;
            };
            self.update_stats(|stats| {
                if location == PersistLocationHit::Primary {
                    stats.primary_hits = stats.primary_hits.saturating_add(1);
                } else {
                    stats.secondary_hits = stats.secondary_hits.saturating_add(1);
                }
                stats.observe_hit_bytes(bytes.len());
            });
            if location != PersistLocationHit::Primary {
                self.promote_record(key, &bytes, "compiled-body secondary hit promotion failed");
            }
            return Some(decoded);
        }
        self.update_stats(|stats| {
            if saw_secondary {
                stats.secondary_misses = stats.secondary_misses.saturating_add(1);
            }
        });
        let net = self.net.as_ref()?;
        let bytes = match memo_net::fetch_compiled_body_record(net, key) {
            memo_net::CompiledBodyFetchOutcome::Hit(bytes) => bytes,
            memo_net::CompiledBodyFetchOutcome::Miss => {
                self.update_stats(|stats| {
                    stats.network_misses = stats.network_misses.saturating_add(1);
                });
                return None;
            }
            memo_net::CompiledBodyFetchOutcome::Error => {
                self.update_stats(|stats| {
                    stats.network_errors = stats.network_errors.saturating_add(1);
                });
                return None;
            }
        };
        let decoded = match decode(&bytes) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.update_stats(|stats| {
                    stats.validation_failures = stats.validation_failures.saturating_add(1);
                });
                tracing::debug!(
                    target: "aos_nix::cache",
                    "compiled-body network record failed semantic or CLIF validation"
                );
                return None;
            }
        };
        self.update_stats(|stats| {
            stats.network_hits = stats.network_hits.saturating_add(1);
            stats.observe_hit_bytes(bytes.len());
        });
        self.promote_record(key, &bytes, "compiled-body network hit promotion failed");
        Some(decoded)
    }

    fn store_record(&self, key: PersistFileArtifactKey, record: &[u8], failure: &'static str) {
        if write_indexed_record(self.locations.primary(), key, record) {
            self.update_stats(|stats| {
                stats.writes = stats.writes.saturating_add(1);
                stats.observe_written_bytes(record.len());
            });
        } else {
            self.update_stats(|stats| stats.write_failures = stats.write_failures.saturating_add(1));
            tracing::debug!(target: "aos_nix::cache", message = failure);
        }
        self.publish_network_record(key, record);
    }

    fn promote_record(&self, key: PersistFileArtifactKey, record: &[u8], failure: &'static str) {
        if write_indexed_record(self.locations.primary(), key, record) {
            self.update_stats(|stats| stats.promotions = stats.promotions.saturating_add(1));
        } else {
            self.update_stats(|stats| {
                stats.promotion_failures = stats.promotion_failures.saturating_add(1);
            });
            tracing::debug!(target: "aos_nix::cache", message = failure);
        }
    }

    fn publish_network_record(&self, key: PersistFileArtifactKey, record: &[u8]) {
        if let Some(net) = self.net.as_ref()
            && net.mode == MemoNetMode::ReadWrite
        {
            if memo_net::publish_compiled_body_record(net, key, record) {
                self.update_stats(|stats| stats.publishes = stats.publishes.saturating_add(1));
            } else {
                self.update_stats(|stats| {
                    stats.publish_failures = stats.publish_failures.saturating_add(1);
                });
            }
        }
    }

    fn update_stats(&self, update: impl FnOnce(&mut CompiledBodyCacheStats)) {
        let mut stats = self.stats.get();
        update(&mut stats);
        self.stats.set(stats);
    }
}

impl NixJitTier1Engine {
    /// Configures compiled-body persistence at one primary cache root.
    ///
    /// This compatibility builder keeps direct engine users on one L2
    /// location. Native evaluator construction uses the internal
    /// multi-location builder to include configured secondary locations and
    /// defensive pack verification.
    #[must_use]
    pub fn with_compiled_body_cache_root(self, persist_root: Option<&Path>) -> Self {
        self.with_compiled_body_cache_locations(persist_root, false, &[], None)
    }

    /// Configures packed compiled-body persistence across all L2 locations.
    #[must_use]
    pub(crate) fn with_compiled_body_cache_locations(
        mut self,
        persist_root: Option<&Path>,
        verify: bool,
        secondaries: &[PersistDiskLocation],
        net: Option<&MemoNetOptions>,
    ) -> Self {
        self.tier2.get_mut().compiled_cache = persist_root
            .and_then(|root| CompiledBodyCache::open_with_net(root, verify, secondaries, net));
        self
    }

    /// Configures compiled-body persistence from active evaluator options.
    #[must_use]
    pub(crate) fn with_compiled_body_cache_options(self, options: &TreeWalkOptions) -> Self {
        self.with_compiled_body_cache_locations(
            options.persist_cache_root(),
            options.persist_cache_verify(),
            options.memo_disk_locations(),
            options.memo_net(),
        )
    }
}

fn encode_record(
    ir: &Ir,
    pattern: IrId,
    body: IrId,
    budget: i64,
    lowering: &JitTier2LambdaLowering,
) -> Option<(PersistFileArtifactKey, Vec<u8>)> {
    let fingerprint = lowered_ir_fingerprint(ir).ok()?;
    let payload = encode_tier2_lambda_lowering(lowering).ok()?;
    let payload_len = u64::try_from(payload.len()).ok()?;
    let mut record = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    record.extend_from_slice(&pattern.as_u32().to_le_bytes());
    record.extend_from_slice(&body.as_u32().to_le_bytes());
    record.extend_from_slice(&budget.to_le_bytes());
    record.extend_from_slice(&fingerprint.as_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&payload);
    Some((record_key(fingerprint, pattern, body, budget), record))
}

fn read_record(
    bytes: &[u8],
    fingerprint: LoweredIrFingerprint,
    pattern: IrId,
    body: IrId,
    budget: i64,
) -> Result<JitTier2LambdaLowering, ReadRecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ReadRecordError);
    }
    let payload = validate_header(bytes, fingerprint, pattern, body, budget)?;
    decode_tier2_lambda_lowering(payload, body).map_err(|_| ReadRecordError)
}

fn chain_record_hash(
    fingerprint: LoweredIrFingerprint,
    semantic_identity: &[u8],
    budget: i64,
) -> CompiledBodyRecordHash {
    let target = compiled_body_target_triple();
    CompiledBodyRecordHash::for_fused_chain_tier2(
        fingerprint,
        semantic_identity,
        budget,
        CHAIN_SCHEMA_VERSION,
        ACTIVE_CRANELIFT_CODEGEN_VERSION,
        &target,
    )
}

fn encode_chain_record(
    record_hash: CompiledBodyRecordHash,
    lowering: &JitTier2ChainLowering,
) -> Option<Vec<u8>> {
    let payload = encode_tier2_chain_lowering(lowering).ok()?;
    let payload_len = u64::try_from(payload.len()).ok()?;
    let mut record = Vec::with_capacity(CHAIN_HEADER_LEN.saturating_add(payload.len()));
    record.extend_from_slice(CHAIN_MAGIC);
    record.extend_from_slice(&CHAIN_SCHEMA_VERSION.to_le_bytes());
    record.extend_from_slice(&record_hash.as_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&payload);
    Some(record)
}

fn read_chain_record(
    bytes: &[u8],
    record_hash: CompiledBodyRecordHash,
    source: IrId,
    arity: u32,
    self_upval: Option<(u32, u32)>,
) -> Result<JitTier2ChainLowering, ReadRecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ReadRecordError);
    }
    let header = bytes.get(..CHAIN_HEADER_LEN).ok_or(ReadRecordError)?;
    if header.get(..8) != Some(CHAIN_MAGIC.as_slice())
        || read_u32(header, 8) != Some(CHAIN_SCHEMA_VERSION)
        || header.get(12..44) != Some(record_hash.as_bytes().as_slice())
    {
        return Err(ReadRecordError);
    }
    let payload_len = read_u64(header, 44).ok_or(ReadRecordError)?;
    let payload = bytes.get(CHAIN_HEADER_LEN..).ok_or(ReadRecordError)?;
    if u64::try_from(payload.len()).ok() != Some(payload_len) {
        return Err(ReadRecordError);
    }
    decode_tier2_chain_lowering(payload, source, arity, self_upval)
        .map_err(|_| ReadRecordError)
}

fn record_key(
    fingerprint: LoweredIrFingerprint,
    pattern: IrId,
    body: IrId,
    budget: i64,
) -> PersistFileArtifactKey {
    let target = compiled_body_target_triple();
    PersistFileArtifactKey::for_compiled_body(CompiledBodyRecordHash::for_unary_tier2(
        fingerprint,
        pattern.as_u32(),
        body.as_u32(),
        budget,
        SCHEMA_VERSION,
        ACTIVE_CRANELIFT_CODEGEN_VERSION,
        &target,
    ))
}

fn read_indexed_record(
    cache: &PersistCache,
    key: PersistFileArtifactKey,
    location: PersistLocationHit,
) -> Option<Vec<u8>> {
    let index_value = match cache.lookup_file_artifact(key) {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                ?location,
                error = %error,
                "compiled-body artifact mapping lookup failed"
            );
            return None;
        }
    };
    match cache.read_file_artifact(index_value) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                ?location,
                error = %error,
                "compiled-body packed payload read failed"
            );
            None
        }
    }
}

fn write_indexed_record(cache: &PersistCache, key: PersistFileArtifactKey, record: &[u8]) -> bool {
    let blob_hash = PersistFileBlobHash::for_payload(record);
    let blob_entry = match cache.ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), record) {
        Ok(entry) => entry,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "compiled-body content blob write failed"
            );
            return false;
        }
    };
    let index_value = PersistFileArtifactIndexValue::new(blob_hash, blob_entry.location());
    match cache.record_file_artifact(PersistFileArtifactIndexEntry::new(key, index_value)) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "compiled-body artifact mapping write failed"
            );
            false
        }
    }
}

#[derive(Clone, Copy)]
struct ReadRecordError;

fn validate_header<'a>(
    bytes: &'a [u8],
    fingerprint: LoweredIrFingerprint,
    pattern: IrId,
    body: IrId,
    budget: i64,
) -> Result<&'a [u8], ReadRecordError> {
    let header = bytes.get(..HEADER_LEN).ok_or(ReadRecordError)?;
    if header.get(..8) != Some(MAGIC.as_slice())
        || read_u32(header, 8) != Some(SCHEMA_VERSION)
        || read_u32(header, 12) != Some(pattern.as_u32())
        || read_u32(header, 16) != Some(body.as_u32())
        || read_i64(header, 20) != Some(budget)
        || header.get(28..60) != Some(fingerprint.as_bytes().as_slice())
    {
        return Err(ReadRecordError);
    }
    let payload_len = read_u64(header, 60).ok_or(ReadRecordError)?;
    let payload = bytes.get(HEADER_LEN..).ok_or(ReadRecordError)?;
    if u64::try_from(payload.len()).ok() != Some(payload_len) {
        return Err(ReadRecordError);
    }
    Ok(payload)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ratchet_core::IrData;
    use ratchet_jit::{
        JitTier2EnvBoundary, TIER2_NATIVE_DEPTH_BUDGET, lower_tier2_curried_chain,
        lower_tier2_self_recursive_lambda, scan_tier2_curried_chain,
    };
    use ratchet_oracle::cache::{PersistCache, PersistLatencyClass};

    use crate::native::tests::test_memo_server::MemoTestServer;

    use super::*;

    #[test]
    fn valid_secondary_body_bypasses_corrupt_primary_and_promotes() {
        let (ir, pattern, body, lowering) = fib_lowering();
        let root = unique_cache_root();
        let primary = root.join("primary");
        let secondary = root.join("secondary");
        let secondary_cache =
            CompiledBodyCache::open(&secondary, false, &[]).expect("secondary cache opens");
        secondary_cache.store(&ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET, &lowering);

        let fingerprint = lowered_ir_fingerprint(&ir).expect("IR fingerprints");
        let key = record_key(fingerprint, pattern, body, TIER2_NATIVE_DEPTH_BUDGET);
        let primary_cache = PersistCache::open(&primary).expect("primary cache opens");
        assert!(write_indexed_record(
            &primary_cache,
            key,
            b"corrupt compiled body",
        ));
        let layered = CompiledBodyCache::open(
            &primary,
            false,
            &[PersistDiskLocation::new(
                PersistLatencyClass::Hdd,
                &secondary,
            )],
        )
        .expect("layered cache opens");

        let decoded = layered
            .load(&ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
            .expect("valid secondary body loads");
        assert_eq!(decoded.source(), body);
        assert_eq!(layered.stats().secondary_hits, 1);
        assert_eq!(layered.stats().promotions, 1);
        assert_eq!(layered.stats().validation_failures, 1);
        let promoted_primary = PersistCache::open(&primary).expect("promoted primary reopens");
        let promoted = read_indexed_record(&promoted_primary, key, PersistLocationHit::Primary)
            .expect("promoted primary has record");
        assert!(
            read_record(
                &promoted,
                fingerprint,
                pattern,
                body,
                TIER2_NATIVE_DEPTH_BUDGET,
            )
            .is_ok(),
            "secondary hit replaces the corrupt primary index tail"
        );
        assert!(primary.join("files/pack.blob").is_file());
        assert!(!primary.join("compiled-bodies").exists());

        fs::remove_dir_all(root).expect("cache roots remove");
    }

    #[test]
    fn valid_secondary_chain_bypasses_corrupt_primary_and_promotes() {
        let (ir, lowering) = add_chain_lowering();
        let identity = b"test:add-chain:operator-env:v1";
        let root = unique_cache_root();
        let primary = root.join("primary-chain");
        let secondary = root.join("secondary-chain");
        let secondary_cache =
            CompiledBodyCache::open(&secondary, false, &[]).expect("secondary cache opens");
        secondary_cache.store_chain(&ir, identity, TIER2_NATIVE_DEPTH_BUDGET, &lowering);

        let fingerprint = lowered_ir_fingerprint(&ir).expect("IR fingerprints");
        let record_hash = chain_record_hash(fingerprint, identity, TIER2_NATIVE_DEPTH_BUDGET);
        let key = PersistFileArtifactKey::for_compiled_body(record_hash);
        let primary_cache = PersistCache::open(&primary).expect("primary cache opens");
        assert!(write_indexed_record(
            &primary_cache,
            key,
            b"corrupt fused chain",
        ));
        let layered = CompiledBodyCache::open(
            &primary,
            false,
            &[PersistDiskLocation::new(
                PersistLatencyClass::Hdd,
                &secondary,
            )],
        )
        .expect("layered cache opens");

        let decoded = layered
            .load_chain(
                &ir,
                identity,
                lowering.source(),
                lowering.arity(),
                lowering.self_upval(),
                TIER2_NATIVE_DEPTH_BUDGET,
            )
            .expect("valid secondary chain loads");
        assert_eq!(decoded.source(), lowering.source());
        assert_eq!(decoded.arity(), 2);
        assert_eq!(layered.stats().secondary_hits, 1);
        assert_eq!(layered.stats().promotions, 1);
        let promoted_primary = PersistCache::open(&primary).expect("promoted primary reopens");
        let promoted = read_indexed_record(&promoted_primary, key, PersistLocationHit::Primary)
            .expect("promoted primary has chain record");
        assert!(
            read_chain_record(
                &promoted,
                record_hash,
                lowering.source(),
                lowering.arity(),
                lowering.self_upval(),
            )
            .is_ok(),
            "secondary chain hit replaces the corrupt primary index tail"
        );
        let wrong_hash = chain_record_hash(
            fingerprint,
            b"different chain identity",
            TIER2_NATIVE_DEPTH_BUDGET,
        );
        assert!(
            read_chain_record(
                &promoted,
                wrong_hash,
                lowering.source(),
                lowering.arity(),
                lowering.self_upval(),
            )
            .is_err(),
            "the envelope must reject a valid chain under the wrong semantic key"
        );
        assert!(primary.join("files/pack.blob").is_file());
        assert!(!primary.join("compiled-bodies").exists());

        fs::remove_dir_all(root).expect("cache roots remove");
    }

    #[test]
    fn network_bodies_publish_reload_verify_and_promote_locally() {
        let _net = crate::native::memo_net::test_guard();
        let server = MemoTestServer::spawn().expect("memo server starts");
        let root = unique_cache_root();
        let publisher_root = root.join("publisher");
        let reader_root = root.join("reader");
        let write_net = net_options(&server, MemoNetMode::ReadWrite);
        let publisher =
            CompiledBodyCache::open_with_net(&publisher_root, false, &[], Some(&write_net))
                .expect("publisher cache opens");

        let (fib_ir, pattern, body, fib) = fib_lowering();
        publisher.store(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET, &fib);
        let (chain_ir, chain) = add_chain_lowering();
        let identity = b"test:network:add-chain:operator-env:v1";
        publisher.store_chain(&chain_ir, identity, TIER2_NATIVE_DEPTH_BUDGET, &chain);
        assert_eq!(publisher.stats().writes, 2);
        assert_eq!(publisher.stats().publishes, 2);
        assert!(publisher.stats().written_bytes > 0);
        assert_eq!(
            server.record_count_with_prefix("/v1/compiled-body/"),
            2,
            "rw mode publishes both compiled-body families"
        );

        let read_net = net_options(&server, MemoNetMode::ReadOnly);
        let read_only_writer = CompiledBodyCache::open_with_net(
            &root.join("read-only-writer"),
            false,
            &[],
            Some(&read_net),
        )
        .expect("read-only cache opens");
        read_only_writer.store_chain(
            &chain_ir,
            b"test:network:read-only-must-not-publish:v1",
            TIER2_NATIVE_DEPTH_BUDGET,
            &chain,
        );
        assert_eq!(
            server.record_count_with_prefix("/v1/compiled-body/"),
            2,
            "read-only mode must never publish compiled bodies"
        );

        let reader = CompiledBodyCache::open_with_net(&reader_root, false, &[], Some(&read_net))
            .expect("reader cache opens");
        let decoded_fib = reader
            .load(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
            .expect("unary body reloads from L3");
        assert_eq!(decoded_fib.source(), body);
        let decoded_chain = reader
            .load_chain(
                &chain_ir,
                identity,
                chain.source(),
                chain.arity(),
                chain.self_upval(),
                TIER2_NATIVE_DEPTH_BUDGET,
            )
            .expect("chain body reloads from L3");
        assert_eq!(decoded_chain.source(), chain.source());
        assert_eq!(reader.stats().network_hits, 2);
        assert_eq!(reader.stats().primary_misses, 2);
        assert_eq!(reader.stats().promotions, 2);
        assert!(reader.stats().hit_bytes > 0);
        assert!(reader_root.join("files/pack.blob").is_file());

        let local = CompiledBodyCache::open(&reader_root, false, &[])
            .expect("promoted local cache reopens");
        assert!(
            local
                .load(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
                .is_some(),
            "accepted unary L3 body is installed locally"
        );
        assert!(
            local
                .load_chain(
                    &chain_ir,
                    identity,
                    chain.source(),
                    chain.arity(),
                    chain.self_upval(),
                    TIER2_NATIVE_DEPTH_BUDGET,
                )
                .is_some(),
            "accepted chain L3 body is installed locally"
        );

        fs::remove_dir_all(root).expect("cache roots remove");
    }

    #[test]
    fn corrupted_or_swapped_network_body_is_an_advisory_miss() {
        let _net = crate::native::memo_net::test_guard();
        let server = MemoTestServer::spawn().expect("memo server starts");
        let root = unique_cache_root();
        let write_net = net_options(&server, MemoNetMode::ReadWrite);
        let publisher =
            CompiledBodyCache::open_with_net(&root.join("publisher"), false, &[], Some(&write_net))
                .expect("publisher cache opens");
        let (fib_ir, pattern, body, fib) = fib_lowering();
        publisher.store(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET, &fib);
        let (chain_ir, chain) = add_chain_lowering();
        let identity = b"test:network:poisoned-chain:v1";
        publisher.store_chain(&chain_ir, identity, TIER2_NATIVE_DEPTH_BUDGET, &chain);

        server.mutate_records(|records| {
            let keys = records
                .keys()
                .filter(|key| key.starts_with("/v1/compiled-body/"))
                .cloned()
                .collect::<Vec<_>>();
            if let [first, second] = keys.as_slice() {
                let first_bytes = records[first].clone();
                let second_bytes = records[second].clone();
                records.insert(first.clone(), second_bytes);
                records.insert(second.clone(), first_bytes);
            }
        });
        let read_net = net_options(&server, MemoNetMode::ReadOnly);
        let reader = CompiledBodyCache::open_with_net(
            &root.join("swapped-reader"),
            false,
            &[],
            Some(&read_net),
        )
        .expect("swapped reader opens");
        assert!(
            reader
                .load(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
                .is_none(),
            "a valid bundle under the wrong semantic key must miss"
        );
        assert!(
            reader
                .load_chain(
                    &chain_ir,
                    identity,
                    chain.source(),
                    chain.arity(),
                    chain.self_upval(),
                    TIER2_NATIVE_DEPTH_BUDGET,
                )
                .is_none(),
            "the swapped chain bundle must miss"
        );
        assert_eq!(reader.stats().network_hits, 0);
        assert_eq!(reader.stats().network_errors, 2);

        server.mutate_records(|records| {
            for (key, bytes) in records.iter_mut() {
                if key.starts_with("/v1/compiled-body/")
                    && let Some(last) = bytes.last_mut()
                {
                    *last ^= 0xff;
                }
            }
        });
        let corrupt_reader = CompiledBodyCache::open_with_net(
            &root.join("corrupt-reader"),
            false,
            &[],
            Some(&read_net),
        )
        .expect("corrupt reader opens");
        assert!(
            corrupt_reader
                .load(&fib_ir, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
                .is_none(),
            "content-hash corruption must miss"
        );
        assert_eq!(corrupt_reader.stats().network_hits, 0);
        assert_eq!(corrupt_reader.stats().network_errors, 1);

        fs::remove_dir_all(root).expect("cache roots remove");
    }

    fn net_options(server: &MemoTestServer, mode: MemoNetMode) -> MemoNetOptions {
        MemoNetOptions {
            endpoint: server.endpoint(),
            mode,
            timeout_ms: 2_000,
        }
    }

    fn fib_lowering() -> (Ir, IrId, IrId, JitTier2LambdaLowering) {
        let parsed = ratchet_oracle::syntax::parse_str(
            "let fib = n: if n < 2 then n else fib (n - 1) + fib (n - 2); in fib 8",
        )
        .expect("fib parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("fib resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("fib lowers");
        let (pattern, body) = ir
            .arena
            .nodes()
            .iter()
            .find_map(|node| match node.data {
                IrData::Lambda { pattern, body, .. } => Some((pattern, body)),
                _ => None,
            })
            .expect("fib lambda exists");
        let lowering =
            lower_tier2_self_recursive_lambda(&ir.arena, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
                .expect("fib tier-2 lowering succeeds");
        (ir, pattern, body, lowering)
    }

    fn add_chain_lowering() -> (Ir, JitTier2ChainLowering) {
        let parsed = ratchet_oracle::syntax::parse_str("let add = x: y: x + y; in add 1 2")
            .expect("add parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("add resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("add lowers");
        let root = ir
            .arena
            .nodes()
            .iter()
            .find_map(|node| match node.data {
                IrData::Lambda { pattern, body, .. }
                    if matches!(
                        ir.arena.node(body).map(|body_node| body_node.data),
                        Some(IrData::Lambda { .. })
                    ) => {
                    Some((pattern, body))
                }
                _ => None,
            })
            .expect("add chain exists");
        let scan = scan_tier2_curried_chain(&ir.arena, &ir.bindings, root.0, root.1)
            .expect("add chain scans");
        let lowering = lower_tier2_curried_chain(
            &ir.arena,
            &ir.bindings,
            &scan,
            None,
            &[],
            JitTier2EnvBoundary::OperatorEnv,
            TIER2_NATIVE_DEPTH_BUDGET,
        )
        .expect("add chain lowers");
        (ir, lowering)
    }

    fn unique_cache_root() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aos-tier2-packed-cache-{}-{now}",
            std::process::id()
        ))
    }
}
