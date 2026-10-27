//! Checks nested lower encodings through genuinely recovered native cache owners.
//!
//! The fresh actor reuses the configured repository, quota helper and publisher.
//! Synthetic lower candidates supply untrusted bytes only; they cannot create
//! readiness, change original publication or grant repository authorization.

use super::{FixtureResult, check_owner, fs};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::{
    codec::{Codec, EncodedChunk, encode_envelope, parse_envelope},
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_linux::{
    configured::NativeCachePlan, configured_sdk, host_cache::NativeReadPolicy, quota_confinement,
};
use terrane_sdk::{
    config::Config,
    role::Role,
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
        IdentityPrefix, RangeCapability, RefCapability, StoreErrorKind, StoreFailure, TokioClock,
        TokioLocalFs,
    },
};

struct Candidates {
    capabilities: Capabilities,
    bodies: BTreeMap<[u8; 32], Vec<u8>>,
    reads: Arc<AtomicUsize>,
}

impl CapabilityReport for Candidates {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl ContentStore for Candidates {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bodies
            .get(
                &identity
                    .terrane_v1_digest()
                    .map_err(|_| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))?,
            )
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Ok(identities
            .iter()
            .map(|id| {
                id.terrane_v1_digest()
                    .is_ok_and(|digest| self.bodies.contains_key(&digest))
            })
            .collect())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

fn identity(bytes: &[u8]) -> FixtureResult<Identity> {
    Ok(TERRANE_V1.calculate(IdentityKind::Chunk, bytes)?)
}

fn compressed(bytes: &[u8], dictionary: &[u8], maximum: usize) -> FixtureResult<Vec<u8>> {
    let encoded = terrane_sdk::codec::encode_chunk(bytes, maximum, 3, Some(dictionary))?;
    let expected = Codec::ZstdDictionary(identity(dictionary)?.terrane_v1_digest()?);
    if parse_envelope(&encoded)?.codec != expected {
        return Err("dictionary fixture did not produce its claimed codec".into());
    }
    Ok(encoded)
}

/// Reports only a fixed stage, result class and original lower request count.
///
/// Raw errors can contain configuration or authority material. These finite
/// labels locate a failed native read without relaxing the fixture's redaction.
fn observed(
    phase: &'static str,
    reads: &AtomicUsize,
    result: Result<Vec<u8>, StoreFailure>,
) -> Result<Vec<u8>, StoreFailure> {
    let class = match &result {
        Ok(_) => "ok",
        Err(error) => match error.kind() {
            StoreErrorKind::Absent(_) => "absent",
            StoreErrorKind::Corrupt(_) => "corrupt",
            StoreErrorKind::Capacity => "capacity",
            StoreErrorKind::Unsupported => "unsupported",
            StoreErrorKind::Unavailable { .. } => "unavailable",
            StoreErrorKind::Invalid(_) => "invalid",
            StoreErrorKind::Denied { .. } => "denied",
            StoreErrorKind::ReadOnly => "read-only",
        },
    };
    eprintln!(
        "NATIVE_DICTIONARY_READ phase={phase} result={class} lower_reads={}",
        reads.load(Ordering::Relaxed),
    );
    result
}

/// Executes cold nested reads and corrupt-terminal refusal with original native owners.
///
/// # Errors
/// Refuses missing original configuration, failed confinement or actual native
/// recovery, incorrect lower requests, changed bytes, partial corrupt admission
/// or any mutation to the original portable publication.
pub(super) fn run(root: &Path, owner: u32, recovered_only: bool) -> FixtureResult<()> {
    check_owner(root, owner)?;
    let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
    drop(configured_sdk::preflight(&config, Role::Serve)?);
    let trusted = config
        .local_repository()
        .ok_or("missing trusted repository")?;
    let host = config.host_tier().ok_or("missing native host tier")?;
    let lower = host
        .domains
        .get(&trusted.domain)
        .and_then(|domain| domain.cache.as_ref())
        .and_then(|cache| cache.lower)
        .ok_or("missing finite lower policy")?;
    let policy = NativeReadPolicy::new(
        Duration::from_millis(lower.budget_ms),
        lower.failure_threshold,
        Duration::from_millis(lower.probe_interval_ms),
    )?;
    let plan = NativeCachePlan::from_host(host, terrane_format::refs::Locality::default())?;
    let before = ["CAPABILITIES", "publication/PORTABLE"]
        .map(|name| fs::read(root.join("bucket").join(name)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let installed = Arc::new(quota_confinement::install()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let result = runtime.block_on(async {
        let original = config.open_local_repository(Role::Serve, TokioLocalFs, TokioClock).await?;
        let profile = original.chunk_profile();
        // Policy cases deliberately share the same public owner. Distinct
        // instance content keeps each cold-read control independent; a fresh
        // recovery actor uses the same instance and therefore the same digests.
        let instance = root.file_name()
            .and_then(|name| name.to_str())
            .ok_or("missing dictionary fixture instance")?;
        let base = format!("native chain terminal dictionary vocabulary {instance} ")
            .repeat(32).into_bytes();
        let middle = format!(
            "native chain terminal dictionary vocabulary {instance} and selected content "
        ).repeat(64).into_bytes();
        let content = format!(
            "native chain terminal dictionary vocabulary {instance} and selected content file "
        ).repeat(128).into_bytes();
        let base_id = identity(&base)?;
        let middle_id = identity(&middle)?;
        let content_id = identity(&content)?;
        let base_body = encode_envelope(EncodedChunk { codec: Codec::Raw, body: &base });
        let middle_body = compressed(&middle, &base, profile.maximum())?;
        let content_body = compressed(&content, &middle, profile.maximum())?;

        let reads = Arc::new(AtomicUsize::new(0));
        let mut caches = plan.open(Arc::clone(&installed)).await?;
        let cache = caches.remove(&trusted.domain).ok_or("missing actual native domain")?;
        let native = cache.into_content();
        if recovered_only {
            // This fresh process has no lower provider. Successful reads must
            // use the original, independently recovered native admissions.
            for (phase, identity, expected) in [
                ("recovered-terminal", &base_id, &base_body),
                ("recovered-middle", &middle_id, &middle_body),
                ("recovered-root", &content_id, &content_body),
            ] {
                if observed(phase, &reads, native.get(identity, None).await)? != *expected {
                    return Err("fresh native recovery changed an original chain encoding".into());
                }
            }
            println!("PASS: fresh confined owner recovers the complete original dictionary chain without a lower provider");
            return Ok(());
        }

        let cold_identities = [base_id.clone(), middle_id.clone(), content_id.clone()];
        if native.has(&cold_identities).await? != [false; 3] {
            return Err("cold dictionary fixture already has native chain residents".into());
        }
        println!("PASS: dictionary instance starts without any native chain residents");

        let bad_base = format!("independent rejected terminal dictionary {instance} ")
            .repeat(32).into_bytes();
        let bad_middle = format!("independent rejected terminal dictionary {instance} middle ")
            .repeat(64).into_bytes();
        let bad_content = format!("independent rejected terminal dictionary {instance} content ")
            .repeat(128).into_bytes();
        let bad_ids = [identity(&bad_base)?, identity(&bad_middle)?, identity(&bad_content)?];
        let bodies = BTreeMap::from([
            (base_id.terrane_v1_digest()?, base_body.clone()),
            (middle_id.terrane_v1_digest()?, middle_body.clone()),
            (content_id.terrane_v1_digest()?, content_body.clone()),
            (bad_ids[0].terrane_v1_digest()?, encode_envelope(EncodedChunk { codec: Codec::Raw, body: b"wrong terminal" })),
            (bad_ids[1].terrane_v1_digest()?, compressed(&bad_middle, &bad_base, profile.maximum())?),
            (bad_ids[2].terrane_v1_digest()?, compressed(&bad_content, &bad_middle, profile.maximum())?),
        ]);
        let driver = native.with_lower(Candidates {
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: terrane_format::refs::Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
            bodies, reads: Arc::clone(&reads),
        }, policy);

        let encoded = observed("lower-root", &reads, driver.get(&content_id, None).await)?;
        if encoded != content_body || reads.load(Ordering::Relaxed) != 3 {
            eprintln!(
                "NATIVE_DICTIONARY_READ phase=lower-root-shape result=mismatch lower_reads={}",
                reads.load(Ordering::Relaxed),
            );
            return Err("native driver did not fetch the exact cold dictionary chain".into());
        }
        let verified = terrane_sdk::codec::decode_verified(
            &encoded, content.len(), profile, true, &content_id, Some(&middle),
        )?;
        if verified.plaintext() != content {
            return Err("native dictionary verification or original dependency encoding changed".into());
        }
        for (phase, identity, expected) in [
            ("resident-terminal", &base_id, &base_body),
            ("resident-middle", &middle_id, &middle_body),
            ("resident-root", &content_id, &content_body),
        ] {
            let actual = observed(phase, &reads, driver.native().get(identity, None).await)?;
            if actual != *expected {
                return Err("native dictionary verification or original dependency encoding changed".into());
            }
        }
        if reads.load(Ordering::Relaxed) != 3 {
            return Err("native dictionary verification or original dependency encoding changed".into());
        }
        println!("PASS: actual confined native lower driver verifies nested dictionary chains before admission");

        match observed("corrupt-lower-root", &reads, driver.get(&bad_ids[2], None).await) {
            Err(error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)) => {}
            _ => return Err("corrupt terminal did not refuse the complete native lower read".into()),
        }
        if reads.load(Ordering::Relaxed) != 6 || driver.native().has(&bad_ids).await? != [false; 3] {
            return Err("corrupt dictionary chain left a partial native admission".into());
        }
        println!("PASS: corrupt terminal dictionary cannot warm a partial native chain");
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    drop(runtime);
    installed.check_current()?;
    result?;

    for (name, expected) in ["CAPABILITIES", "publication/PORTABLE"]
        .into_iter()
        .zip(before)
    {
        if fs::read(root.join("bucket").join(name))? != expected {
            return Err("native lower verification changed original publication".into());
        }
    }
    Ok(())
}
