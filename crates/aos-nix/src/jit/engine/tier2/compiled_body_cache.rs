//! Packed, multi-location persistence for address-free tier-2 bodies.
//!
//! Compiled bodies share the evaluator's indexed `files/pack.blob` store and
//! probe the configured L2 locations in latency order. A verified secondary
//! hit is promoted through the primary's ordinary indexed-write path. Missing,
//! unreadable, corrupt, source-mismatched, or verifier-rejected records are
//! advisory misses; executable pages and process addresses are never stored.

#[cfg(test)]
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
use ratchet_oracle::eval::tree_walk::TreeWalkOptions;

use super::NixJitTier1Engine;

const MAGIC: &[u8; 8] = b"AOSJIT2\0";
const SCHEMA_VERSION: u32 = 2;
const HEADER_LEN: usize = 68;
const CHAIN_MAGIC: &[u8; 8] = b"AOSJTC1\0";
const CHAIN_SCHEMA_VERSION: u32 = 1;
const CHAIN_HEADER_LEN: usize = 52;
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

pub(in crate::jit::engine) struct CompiledBodyCache {
    locations: PersistCacheLocations,
    #[cfg(test)]
    chain_hits: Cell<u64>,
}

impl CompiledBodyCache {
    fn open(
        persist_root: &Path,
        verify: bool,
        secondaries: &[PersistDiskLocation],
    ) -> Option<Self> {
        match PersistCacheLocations::open(persist_root, verify, secondaries) {
            Ok(locations) => Some(Self {
                locations,
                #[cfg(test)]
                chain_hits: Cell::new(0),
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
        for (location, cache) in self.locations.iter() {
            let Some(bytes) = read_indexed_record(cache, key, location) else {
                continue;
            };
            let Ok(lowering) = read_record(&bytes, fingerprint, pattern, body, budget) else {
                continue;
            };
            if location != PersistLocationHit::Primary
                && !write_indexed_record(self.locations.primary(), key, &bytes)
            {
                tracing::debug!(
                    target: "aos_nix::cache",
                    ?location,
                    "compiled-body secondary hit promotion failed"
                );
            }
            return Some(lowering);
        }
        None
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
        if !write_indexed_record(self.locations.primary(), key, &record) {
            tracing::debug!(
                target: "aos_nix::cache",
                "compiled-body indexed write failed"
            );
        }
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
        for (location, cache) in self.locations.iter() {
            let Some(bytes) = read_indexed_record(cache, key, location) else {
                continue;
            };
            let Ok(lowering) = read_chain_record(
                &bytes,
                record_hash,
                source,
                arity,
                self_upval,
            ) else {
                continue;
            };
            if location != PersistLocationHit::Primary
                && !write_indexed_record(self.locations.primary(), key, &bytes)
            {
                tracing::debug!(
                    target: "aos_nix::cache",
                    ?location,
                    "fused-chain compiled-body secondary hit promotion failed"
                );
            }
            #[cfg(test)]
            self.chain_hits.set(self.chain_hits.get().saturating_add(1));
            return Some(lowering);
        }
        None
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
        if !write_indexed_record(self.locations.primary(), key, &record) {
            tracing::debug!(
                target: "aos_nix::cache",
                "fused-chain compiled-body indexed write failed"
            );
        }
    }

    /// Returns successful chain reloads observed by this test cache instance.
    #[cfg(test)]
    pub(in crate::jit::engine) fn chain_hits(&self) -> u64 {
        self.chain_hits.get()
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
        self.with_compiled_body_cache_locations(persist_root, false, &[])
    }

    /// Configures packed compiled-body persistence across all L2 locations.
    #[must_use]
    pub(crate) fn with_compiled_body_cache_locations(
        mut self,
        persist_root: Option<&Path>,
        verify: bool,
        secondaries: &[PersistDiskLocation],
    ) -> Self {
        self.tier2.get_mut().compiled_cache =
            persist_root.and_then(|root| CompiledBodyCache::open(root, verify, secondaries));
        self
    }

    /// Configures compiled-body persistence from active evaluator options.
    #[must_use]
    pub(crate) fn with_compiled_body_cache_options(self, options: &TreeWalkOptions) -> Self {
        self.with_compiled_body_cache_locations(
            options.persist_cache_root(),
            options.persist_cache_verify(),
            options.memo_disk_locations(),
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
        assert_eq!(layered.chain_hits(), 1);
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
