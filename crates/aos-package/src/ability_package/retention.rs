//! Live Nix-store verification for authenticated ability retention catalogs.
//!
//! The verifier compares signed catalog identities with complete NAR streams,
//! direct references, and transitive closure membership from `nix-store`. Every
//! subprocess has bounded output and a fixed deadline so publication and native
//! execution fail closed without accumulating unreaped children.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aos_contract::Sha256Digest;
use aos_core::nix::aos_nix_env;
use sha2::{Digest as _, Sha256};

use super::{AbilityRetentionVerifier, VerifiedAbilityRetentionManifest};

const STORE_VERIFY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const STORE_VERIFY_ERROR_LIMIT: u64 = 64 * 1024;
const STORE_VERIFY_OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

/// Checks authenticated ability retention catalogs against the live Nix store.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeAbilityRetentionVerifier;

impl NativeAbilityRetentionVerifier {
    /// Constructs the production live-store retention verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AbilityRetentionVerifier for NativeAbilityRetentionVerifier {
    fn verify_retention(&self, retention: &VerifiedAbilityRetentionManifest) -> anyhow::Result<()> {
        use anyhow::Context as _;

        verify_store_object(
            retention.companion_store_path(),
            retention.companion_nar_hash(),
            retention.companion_nar_size(),
            retention.companion_references(),
        )?;

        for artifact in retention.artifacts() {
            let actual_closure =
                query_store_paths(&["--query", "--requisites"], &artifact.store_path)?;
            let expected_closure = artifact
                .closure
                .iter()
                .map(|member| member.store_path.clone())
                .collect::<Vec<_>>();
            anyhow::ensure!(
                actual_closure == expected_closure,
                "ability artifact {} live closure differs from its authenticated catalog",
                artifact.store_path
            );

            for member in &artifact.closure {
                let expected_hash = Sha256Digest::parse(&member.nar_hash)
                    .with_context(|| format!("decoding NAR identity for {}", member.store_path))?;
                verify_store_object(
                    &member.store_path,
                    expected_hash,
                    member.nar_size,
                    &member.references,
                )?;
            }
        }
        Ok(())
    }
}

fn verify_store_object(
    store_path: &str,
    expected_hash: Sha256Digest,
    expected_size: u64,
    expected_references: &[String],
) -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};

    let (root, suffix) = crate::config_eval::stock::store_root_and_suffix(Path::new(store_path))
        .context("retention member does not name a canonical Nix store path")?;
    ensure!(
        suffix.as_os_str().is_empty(),
        "retention member is not a store root"
    );
    ensure!(
        root.as_os_str() == std::ffi::OsStr::new(store_path),
        "retention member path is not canonical"
    );
    run_store_check(store_path, &["--check-validity"])?;

    let (actual_hash, actual_size) = dump_store_path_identity(store_path)?;
    ensure!(
        actual_hash == expected_hash,
        "store object {store_path} NAR mismatch: expected {expected_hash}, observed {actual_hash}"
    );
    ensure!(
        actual_size == expected_size,
        "store object {store_path} NAR size mismatch: expected {expected_size}, observed {actual_size}"
    );

    let actual_references = query_reference_hashes(store_path)?;
    ensure!(
        actual_references == expected_references,
        "store object {store_path} direct references differ from its authenticated catalog"
    );
    Ok(())
}

pub(crate) fn run_store_check(store_path: &str, arguments: &[&str]) -> anyhow::Result<()> {
    use anyhow::{Context as _, bail};

    let status = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(arguments)
        .arg(store_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting nix-store {} {store_path}", arguments.join(" ")))?;
    let (status, stderr) = wait_for_store_command(status)?;
    if !status.success() {
        bail!(
            "nix-store {} {store_path} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn query_store_paths(
    arguments: &[&str],
    store_path: &str,
) -> anyhow::Result<Vec<String>> {
    use anyhow::{Context as _, ensure};

    let mut paths = run_store_query(store_path, arguments)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for path in &paths {
        let (root, suffix) = crate::config_eval::stock::store_root_and_suffix(Path::new(path))
            .with_context(|| format!("nix-store returned malformed path {path:?}"))?;
        ensure!(
            suffix.as_os_str().is_empty(),
            "nix-store returned a path suffix"
        );
        ensure!(
            root.as_os_str() == std::ffi::OsStr::new(path),
            "nix-store returned a noncanonical path"
        );
    }
    paths.sort();
    let original_len = paths.len();
    paths.dedup();
    ensure!(
        paths.len() == original_len,
        "nix-store returned a duplicate store path"
    );
    Ok(paths)
}

pub(crate) fn query_reference_hashes(store_path: &str) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;

    let references = query_store_paths(&["--query", "--references"], store_path)?;
    references
        .into_iter()
        .filter(|reference| reference != store_path)
        .map(|reference| {
            let name = Path::new(&reference)
                .file_name()
                .and_then(|name| name.to_str())
                .with_context(|| {
                    format!("store reference has no UTF-8 object name: {reference}")
                })?;
            let hash = name
                .get(..32)
                .context("validated store reference has no 32-byte hash prefix")?;
            Ok(hash.to_string())
        })
        .collect()
}

fn run_store_query(store_path: &str, arguments: &[&str]) -> anyhow::Result<String> {
    use anyhow::{Context as _, bail};

    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(arguments)
        .arg(store_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting nix-store {} {store_path}", arguments.join(" ")))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        bail!("nix-store query stdout was not piped");
    };
    let output = thread::spawn(move || read_bounded(stdout, STORE_VERIFY_OUTPUT_LIMIT));
    let process_result = wait_for_store_command(child);
    let output_result = output
        .join()
        .map_err(|_| anyhow::anyhow!("nix-store stdout worker panicked"))?;
    let (status, stderr) = process_result?;
    let output = output_result?;
    if !status.success() {
        bail!(
            "nix-store {} {store_path} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    String::from_utf8(output).context("nix-store query output is not UTF-8")
}

pub(crate) fn dump_store_path_identity(store_path: &str) -> anyhow::Result<(Sha256Digest, u64)> {
    use anyhow::{Context as _, bail};

    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--dump", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting nix-store --dump {store_path}"))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        anyhow::bail!("nix-store --dump stdout was not piped");
    };
    let digest = thread::spawn(move || {
        let mut reader = stdout;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("NAR size overflow"))?;
            hasher.update(&buffer[..count]);
        }
        Ok::<_, std::io::Error>((hasher.finalize(), size))
    });
    let process_result = wait_for_store_command(child);
    let digest_result = digest
        .join()
        .map_err(|_| anyhow::anyhow!("NAR digest worker panicked"))?;
    let (status, stderr) = process_result?;
    let (digest, size) = digest_result?;
    if !status.success() {
        bail!(
            "nix-store --dump {store_path} failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    let digest = Sha256Digest::from_bytes(digest.into());
    Ok((digest, size))
}

#[allow(
    clippy::disallowed_methods,
    reason = "nix-store subprocess deadlines use host monotonic time outside replayable ability state"
)]
fn wait_for_store_command(
    mut child: std::process::Child,
) -> anyhow::Result<(std::process::ExitStatus, Vec<u8>)> {
    use anyhow::Context as _;

    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child);
        anyhow::bail!("nix-store stderr was not piped");
    };
    let stderr = thread::spawn(move || read_bounded(stderr, STORE_VERIFY_ERROR_LIMIT));
    let deadline = Instant::now() + STORE_VERIFY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                break Err(anyhow::anyhow!(
                    "nix-store verification exceeded {} seconds",
                    STORE_VERIFY_TIMEOUT.as_secs()
                ));
            }
            Err(source) => break Err(source).context("polling nix-store"),
        }
    };
    if status.is_err() {
        // Dropping Child does not terminate or reap it. Close the process before
        // joining readers so every error path retains subprocess ownership.
        terminate_and_reap(&mut child);
    }
    let stderr_result = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("nix-store stderr worker panicked"))?;
    let status = status?;
    let mut stderr = stderr_result?;
    if stderr.len() > STORE_VERIFY_ERROR_LIMIT as usize {
        stderr.truncate(STORE_VERIFY_ERROR_LIMIT as usize);
    }
    Ok((status, stderr))
}

fn read_bounded(mut reader: impl Read, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let capacity = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut retained = Vec::with_capacity(capacity.min(64 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if retained.len() < capacity {
            let remaining = capacity - retained.len();
            retained.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
    if total > limit {
        return Err(std::io::Error::other(format!(
            "subprocess output exceeds {limit} bytes"
        )));
    }
    Ok(retained)
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;

    use super::*;
    use crate::ability_package::seal_test_retention_manifest;
    use crate::types::{
        AbilityArtifactRetentionMeta, AbilityClosureMemberMeta, AbilityPackageMeta,
    };

    const TEST_CLOSURE_DIGEST_DOMAIN: &str = "aos.ability.closure/v1";

    fn live_closure_member(store_path: &str) -> anyhow::Result<AbilityClosureMemberMeta> {
        let (nar_hash, nar_size) = dump_store_path_identity(store_path)?;
        Ok(AbilityClosureMemberMeta {
            store_path: store_path.to_string(),
            nar_hash: nar_hash.to_string(),
            nar_size,
            references: query_reference_hashes(store_path)?,
        })
    }

    fn live_ability_fixture(store_path: &str) -> anyhow::Result<AbilityPackageMeta> {
        let companion = live_closure_member(store_path)?;
        let mut closure = query_store_paths(&["--query", "--requisites"], store_path)?
            .iter()
            .map(|member| live_closure_member(member))
            .collect::<anyhow::Result<Vec<_>>>()?;
        closure.sort();
        let closure_digest = Sha256Digest::of_canonical(TEST_CLOSURE_DIGEST_DOMAIN, &closure)?;
        let content = Sha256Digest::of_bytes(store_path.as_bytes());

        Ok(AbilityPackageMeta {
            store_path: store_path.to_string(),
            nar_hash: companion.nar_hash.clone(),
            nar_size: companion.nar_size,
            references: companion.references,
            manifest_sha256: Sha256Digest::of_bytes(b"test manifest").to_string(),
            manifest_size: 1,
            package_digest: Sha256Digest::of_bytes(b"test package").to_string(),
            activation_mode: "contracts-only".to_string(),
            artifacts: vec![AbilityArtifactRetentionMeta {
                content: content.to_string(),
                store_path: store_path.to_string(),
                nar_hash: companion.nar_hash,
                nar_size: companion.nar_size,
                closure_digest: closure_digest.to_string(),
                closure,
            }],
            provenance: "provenance/test.ability.intoto.jsonl".to_string(),
        })
    }

    fn refresh_test_closure_digest(ability: &mut AbilityPackageMeta) {
        ability.artifacts[0].closure.sort();
        ability.artifacts[0].closure_digest =
            Sha256Digest::of_canonical(TEST_CLOSURE_DIGEST_DOMAIN, &ability.artifacts[0].closure)
                .unwrap()
                .to_string();
    }

    #[test]
    fn native_retention_verifier_checks_real_aos_store_catalog() -> anyhow::Result<()> {
        let Ok(store_path) = std::env::var("AOS_TEST_ABILITY_REFERENCE_NGINX") else {
            return Ok(());
        };
        let verifier = NativeAbilityRetentionVerifier::new();
        let ability = live_ability_fixture(&store_path)?;
        verifier.verify_retention(&seal_test_retention_manifest(&ability)?)?;

        let mut wrong_nar = ability.clone();
        wrong_nar.artifacts[0].nar_hash = Sha256Digest::of_bytes(b"wrong nar").to_string();
        let wrong_nar_hash = wrong_nar.artifacts[0].nar_hash.clone();
        let root = wrong_nar.artifacts[0]
            .closure
            .iter_mut()
            .find(|member| member.store_path == store_path)
            .context("real fixture closure does not contain its root")?;
        root.nar_hash = wrong_nar_hash;
        refresh_test_closure_digest(&mut wrong_nar);
        let error = verifier
            .verify_retention(&seal_test_retention_manifest(&wrong_nar)?)
            .expect_err("a tampered closure-member NAR must fail closed");
        assert!(format!("{error:#}").contains("NAR mismatch"));

        let mut wrong_references = ability.clone();
        let root = wrong_references.artifacts[0]
            .closure
            .iter_mut()
            .find(|member| member.store_path == store_path)
            .context("real fixture closure does not contain its root")?;
        if root.references.pop().is_none() {
            let object_name = Path::new(&store_path)
                .file_name()
                .and_then(|name| name.to_str())
                .context("real fixture has no UTF-8 store object name")?;
            root.references.push(
                object_name
                    .get(..32)
                    .context("real fixture has no store hash prefix")?
                    .to_string(),
            );
        }
        refresh_test_closure_digest(&mut wrong_references);
        let error = verifier
            .verify_retention(&seal_test_retention_manifest(&wrong_references)?)
            .expect_err("tampered direct references must fail closed");
        assert!(format!("{error:#}").contains("direct references differ"));

        let mut missing = ability;
        let missing_path = "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-missing-ability-artifact";
        missing.artifacts[0].store_path = missing_path.to_string();
        let root = missing.artifacts[0]
            .closure
            .iter_mut()
            .find(|member| member.store_path == store_path)
            .context("real fixture closure does not contain its root")?;
        root.store_path = missing_path.to_string();
        refresh_test_closure_digest(&mut missing);
        let error = verifier
            .verify_retention(&seal_test_retention_manifest(&missing)?)
            .expect_err("a missing retained root must fail closed");
        assert!(format!("{error:#}").contains("nix-store --query --requisites"));
        Ok(())
    }
}
