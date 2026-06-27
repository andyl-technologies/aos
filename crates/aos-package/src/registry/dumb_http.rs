//! Pure-Rust dumb-HTTP(S) fetcher for static SHA-256 registries.
//!
//! libgit2 implements only the *smart* HTTP protocol and rejects a static
//! object tree (it requires the `application/x-git-upload-pack-advertisement`
//! content-type). AOS registries are served as a static *dumb*-HTTP layout —
//! `HEAD`, `info/refs`, and a complete set of loose objects under
//! `objects/<2>/<62>` (apr's `ensure_loose_completeness` guarantees every
//! reachable object has a loose copy). This module reads that layout directly.
//!
//! # Wire format
//!
//! ```text
//! GET <base>/info/refs        ->  "<oid>\t<refname>\n" lines (peeled "^{}"
//!                                 lines for annotated tags are ignored)
//! GET <base>/HEAD             ->  "ref: refs/heads/<branch>\n"  (or a bare oid)
//! GET <base>/objects/info/packs -> "P pack-<hash>.pack\n" lines
//! GET <base>/objects/pack/pack-<hash>.pack -> raw packfile
//! GET <base>/objects/<oid[0:2]>/<oid[2:]>  -> a zlib-compressed loose object:
//!                                 inflate -> "<type> <size>\0<body>"
//! ```
//!
//! # Algorithm
//!
//! Refs are resolved to OIDs via `info/refs`/`HEAD`. Then, in two phases:
//!
//! 1. **Packs (fast path).** Every pack listed in `objects/info/packs` is
//!    downloaded concurrently and indexed with libgit2's pack writer
//!    (equivalent to `git index-pack`, which regenerates and verifies the
//!    `.idx`). A registry's whole reachable graph is usually one or a few
//!    packs, so this replaces thousands of per-object round trips.
//! 2. **Loose (completeness fallback).** The graph reachable from the targets
//!    is walked through the local object store (see
//!    `repo::missing_objects_blocking`); whatever the packs did not cover is
//!    fetched as loose objects (verified against their SHA-256) and the walk
//!    repeats to a fixpoint. A registry's dumb-HTTP layout guarantees loose
//!    completeness, so this always terminates with the full graph local.
//!
//! Finally the destination refs are set. Object *content* integrity is enforced
//! here (loose objects by hash, packed objects by the indexer's content
//! addressing); *commit* trust (signatures, fast-forward) is enforced by the
//! caller after the fetch, exactly as for the smart transports.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use futures_util::stream::{self, StreamExt};
use sha2::{Digest, Sha256};

use crate::download::join_cache_url;
use crate::registry::repo;

/// Upper bound on objects fetched in a single sync, a backstop against a
/// malicious or broken origin advertising an unbounded graph. Real registries
/// are far smaller; the visited set already prevents cycles.
const MAX_OBJECTS: usize = 2_000_000;

/// Maximum object downloads in flight at once. Dumb-HTTP is latency-bound (one
/// GET per object), so the graph walk fetches each breadth-first level
/// concurrently; this caps the fan-out to stay friendly to static origins
/// (S3/garage/nginx) while still hiding round-trip latency.
const MAX_CONCURRENCY: usize = 24;

/// Fetch `refspecs` from a dumb-HTTP(S) registry at `base_url` into the bare
/// repository at `repo_dir`.
///
/// `refspecs` use git's `src:dst` form (a leading `+` for force is accepted and
/// ignored — refs are always overwritten). A `src` with no `:dst` fetches the
/// objects without creating a local ref (used for commit-pinned tracking). A
/// trailing `/*` wildcard expands over matching advertised refs.
///
/// # Errors
///
/// Returns an error if the origin is unreachable, advertises a malformed
/// `info/refs`, serves an object whose content does not match its OID, or a
/// requested ref cannot be resolved.
pub(crate) async fn fetch(repo_dir: &Path, base_url: &str, refspecs: &[String]) -> Result<()> {
    let client = reqwest::Client::new();
    let advertised = fetch_info_refs(&client, base_url).await?;
    let head = fetch_head_oid(&client, base_url, &advertised).await?;

    // Resolve every refspec to (oid, optional destination ref).
    let mut targets: Vec<(String, Option<String>)> = Vec::new();
    for spec in refspecs {
        resolve_refspec(spec, &advertised, head.as_deref(), &mut targets)?;
    }

    let target_oids: Vec<String> = targets.iter().map(|(oid, _)| oid.clone()).collect();
    let objects_dir = repo::objects_dir(repo_dir);

    // Walk the local graph first: a repeat sync with no upstream change finds
    // nothing missing and downloads no objects at all — only the refs (below)
    // may need re-pointing.
    let mut missing = walk_missing(repo_dir, &target_oids).await?;

    if !missing.is_empty() {
        // Pack phase (fast path): download + index advertised packs we do not
        // already have. A handful of large requests instead of one round trip
        // per loose object; libgit2's indexer verifies each pack on commit.
        let advertised = fetch_pack_list(&client, base_url).await?;
        let pack_dir = objects_dir.join("pack");
        let new_packs: Vec<String> = advertised
            .into_iter()
            .filter(|name| !pack_dir.join(name).exists())
            .collect();
        if !new_packs.is_empty() {
            let client = &client;
            let packs: Vec<Vec<u8>> = stream::iter(new_packs.into_iter())
                .map(|name| async move { fetch_pack(client, base_url, &name).await })
                .buffer_unordered(MAX_CONCURRENCY)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            let repo_path = repo_dir.to_path_buf();
            // The pack phase is a fast-path optimization. libgit2's streaming
            // indexer can intermittently reject an otherwise-complete pack with a
            // generic write error; rather than failing the whole sync, fall
            // through to the loose phase below, which fetches and individually
            // hash-verifies every still-missing object (the dumb-HTTP layout
            // guarantees loose completeness). On success, prune what the pack
            // already covered so the loose phase only fetches the remainder.
            let indexed =
                tokio::task::spawn_blocking(move || repo::index_packs_blocking(&repo_path, &packs))
                    .await
                    .context("pack-indexing task panicked")?;
            if indexed.is_ok() {
                missing = walk_missing(repo_dir, &target_oids).await?;
            }
        }

        // Loose fallback: fetch whatever the packs did not cover (a registry's
        // dumb-HTTP layout guarantees loose completeness). Each round downloads
        // the current missing frontier concurrently; reading a fetched object
        // can reveal deeper references, so it iterates to a fixpoint.
        let mut total_fetched = 0usize;
        while !missing.is_empty() {
            total_fetched += missing.len();
            if total_fetched > MAX_OBJECTS {
                bail!("registry object graph exceeded {MAX_OBJECTS} objects; refusing to continue");
            }
            let client = &client;
            let objects_dir = &objects_dir;
            stream::iter(missing.into_iter())
                .map(|oid| async move { fetch_loose(client, base_url, objects_dir, &oid).await })
                .buffer_unordered(MAX_CONCURRENCY)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            missing = walk_missing(repo_dir, &target_oids).await?;
        }
    }

    // Point destination refs at the resolved OIDs.
    let mut ref_writes: Vec<(String, String)> = Vec::new();
    for (oid, dst) in targets {
        if let Some(dst) = dst {
            ref_writes.push((dst, oid));
        }
    }
    if !ref_writes.is_empty() {
        let repo_dir = repo_dir.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<()> {
            for (refname, oid) in ref_writes {
                repo::set_reference(&repo_dir, &refname, &oid)?;
            }
            Ok(())
        })
        .await
        .context("ref-writing task panicked")??;
    }

    Ok(())
}

/// Walk the local object graph and return the OIDs reachable from `targets`
/// that are still absent. Runs the (blocking) libgit2 walk off-runtime.
async fn walk_missing(repo_dir: &Path, targets: &[String]) -> Result<Vec<String>> {
    let repo_path = repo_dir.to_path_buf();
    let targets = targets.to_vec();
    tokio::task::spawn_blocking(move || repo::missing_objects_blocking(&repo_path, &targets))
        .await
        .context("object-walk task panicked")?
}

/// Maximum attempts for a single GET before giving up. Exponential backoff
/// (100ms, 200ms, ... up to ~3.1s total) absorbs transient network blips and a
/// briefly-starved or slow origin.
const MAX_ATTEMPTS: usize = 6;

/// GET `url`, retrying transient failures with exponential backoff, and return
/// the final `(status, body)`.
///
/// The request **and** the body read are retried together: a response that is
/// truncated or interrupted mid-body under load (a common failure when many
/// objects are fetched concurrently) is re-fetched rather than surfacing as a
/// short read — which previously corrupted a downloaded pack and made indexing
/// fail. `error_for_status` is not applied, so callers can treat 404 as
/// "absent".
///
/// # Errors
///
/// Returns an error if every attempt fails to complete the request or read its
/// body.
async fn get_with_retry(
    client: &reqwest::Client,
    url: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let outcome = async {
            let response = client.get(url).send().await?;
            let status = response.status();
            let body = response.bytes().await?;
            Ok::<_, reqwest::Error>((status, body))
        }
        .await;
        match outcome {
            Ok((status, _)) if status.is_server_error() && attempt < MAX_ATTEMPTS => {}
            Ok((status, body)) => return Ok((status, body.to_vec())),
            Err(err) if attempt < MAX_ATTEMPTS && is_transient(&err) => {}
            Err(err) => return Err(err).with_context(|| format!("fetching {url}")),
        }
        // Backoff: 100ms, 200ms, 400ms, ...
        let backoff = std::time::Duration::from_millis(100 << (attempt - 1));
        tokio::time::sleep(backoff).await;
    }
}

/// `true` for reqwest errors worth retrying: connection, timeout, request-send,
/// and incomplete-body/decode failures (the latter cover truncated responses
/// under concurrent load).
fn is_transient(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request() || err.is_body() || err.is_decode()
}

/// Download one missing object and install it as a loose file.
///
/// Downloads the compressed object, verifies its SHA-256 matches `oid` (the
/// inflated bytes are git's `"<type> <size>\0<body>"` pre-image), and writes it
/// verbatim under `objects/<2>/<62>`.
async fn fetch_loose(
    client: &reqwest::Client,
    base_url: &str,
    objects_dir: &Path,
    oid: &str,
) -> Result<()> {
    let loose_path = loose_object_path(objects_dir, oid)?;
    let compressed = fetch_object(client, base_url, oid).await?;
    let inflated = inflate(&compressed).with_context(|| format!("inflating object {oid}"))?;
    verify_oid(oid, &inflated)?;
    write_loose_verbatim(&loose_path, &compressed).await
}

/// Fetch the list of packfile names from `objects/info/packs`.
///
/// The file holds `P pack-<hash>.pack` lines. A missing file (404) means the
/// origin serves no packs (loose-only), returning an empty list.
async fn fetch_pack_list(client: &reqwest::Client, base_url: &str) -> Result<Vec<String>> {
    let url = join_cache_url(base_url, "objects/info/packs");
    let (status, body) = get_with_retry(client, &url).await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        bail!("fetching {url} failed with {status}");
    }
    let body = String::from_utf8_lossy(&body);

    let mut names = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        // Lines are "P <pack-name>.pack"; ignore blanks and other markers.
        if let Some(name) = line.strip_prefix("P ") {
            let name = name.trim();
            if name.ends_with(".pack") && is_safe_pack_name(name) {
                names.push(name.to_string());
            } else {
                bail!("malformed pack name in objects/info/packs: {name:?}");
            }
        }
    }
    Ok(names)
}

/// Download one packfile's raw bytes from `objects/pack/<name>`.
///
/// Only the `.pack` is fetched; libgit2's indexer regenerates and verifies the
/// `.idx`, so a server-supplied index is never trusted.
async fn fetch_pack(client: &reqwest::Client, base_url: &str, name: &str) -> Result<Vec<u8>> {
    let url = join_cache_url(base_url, &format!("objects/pack/{name}"));
    let (status, body) = get_with_retry(client, &url).await?;
    if !status.is_success() {
        bail!("fetching pack {name} failed with {status}");
    }
    Ok(body)
}

/// `true` for a `pack-<hex>.pack` name with no path-traversal characters.
fn is_safe_pack_name(name: &str) -> bool {
    name.starts_with("pack-")
        && !name.contains('/')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

/// Fetch and parse `info/refs` into a `refname -> oid` map.
///
/// Peeled `^{}` lines (annotated-tag commit targets) are skipped; the tag
/// object itself is walked.
async fn fetch_info_refs(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<HashMap<String, String>> {
    let url = join_cache_url(base_url, "info/refs");
    let (status, body) = get_with_retry(client, &url).await?;
    if !status.is_success() {
        bail!("fetching {url} failed with {status}");
    }
    let body = String::from_utf8_lossy(&body);

    let mut map = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (oid, name) = line
            .split_once('\t')
            .with_context(|| format!("malformed info/refs line: {line:?}"))?;
        if name.ends_with("^{}") {
            continue;
        }
        validate_oid(oid)?;
        map.insert(name.to_string(), oid.to_string());
    }
    Ok(map)
}

/// Resolve the origin `HEAD` to an OID via the `HEAD` file's symref (or a bare
/// OID). Returns `None` if `HEAD` is absent or unresolvable.
async fn fetch_head_oid(
    client: &reqwest::Client,
    base_url: &str,
    advertised: &HashMap<String, String>,
) -> Result<Option<String>> {
    let url = join_cache_url(base_url, "HEAD");
    let (status, body) = get_with_retry(client, &url).await?;
    if !status.is_success() {
        return Ok(None);
    }
    let body = String::from_utf8_lossy(&body);
    let body = body.trim();
    if let Some(refname) = body.strip_prefix("ref: ") {
        return Ok(advertised.get(refname.trim()).cloned());
    }
    if validate_oid(body).is_ok() {
        return Ok(Some(body.to_string()));
    }
    Ok(None)
}

/// Expand one refspec into `(oid, optional dst-ref)` targets.
fn resolve_refspec(
    spec: &str,
    advertised: &HashMap<String, String>,
    head: Option<&str>,
    out: &mut Vec<(String, Option<String>)>,
) -> Result<()> {
    let spec = spec.strip_prefix('+').unwrap_or(spec);
    let (src, dst) = match spec.split_once(':') {
        Some((src, dst)) => (src, Some(dst)),
        None => (spec, None),
    };

    // Wildcard refspec, e.g. refs/tags/*:refs/tags/*.
    if let (Some(src_prefix), Some(dst)) = (src.strip_suffix('*'), dst) {
        let dst_prefix = dst
            .strip_suffix('*')
            .context("wildcard source needs a wildcard destination")?;
        for (name, oid) in advertised {
            if let Some(rest) = name.strip_prefix(src_prefix) {
                out.push((oid.clone(), Some(format!("{dst_prefix}{rest}"))));
            }
        }
        return Ok(());
    }

    let oid = if src == "HEAD" {
        head.context("origin advertises no resolvable HEAD")?
            .to_string()
    } else if validate_oid(src).is_ok() {
        src.to_string()
    } else if let Some(oid) = advertised.get(src) {
        oid.clone()
    } else {
        bail!("registry origin does not advertise ref {src}");
    };
    out.push((oid, dst.map(str::to_string)));
    Ok(())
}

/// Download a single loose object (zlib-compressed bytes).
async fn fetch_object(client: &reqwest::Client, base_url: &str, oid: &str) -> Result<Vec<u8>> {
    let path = format!("objects/{}/{}", &oid[..2], &oid[2..]);
    let url = join_cache_url(base_url, &path);
    let (status, body) = get_with_retry(client, &url).await?;
    if !status.is_success() {
        bail!("fetching object {oid} failed with {status}");
    }
    Ok(body)
}

/// Inflate a zlib-compressed loose object into `"<type> <size>\0<body>"`.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("zlib decompression failed")?;
    Ok(out)
}

/// Verify that the inflated object hashes to `oid` under git's SHA-256 object
/// id (the inflated bytes already are git's `"<type> <size>\0<body>"`
/// pre-image).
fn verify_oid(oid: &str, inflated: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(inflated);
    let computed = hex::encode(hasher.finalize());
    if computed != oid {
        bail!("object {oid} content hash mismatch (got {computed}); registry may be corrupt");
    }
    Ok(())
}

/// Write the compressed object verbatim to its loose path, creating the fanout
/// directory. Writes are atomic via a temp file rename so a concurrent reader
/// never sees a partial object.
async fn write_loose_verbatim(loose_path: &Path, compressed: &[u8]) -> Result<()> {
    if let Some(parent) = loose_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = loose_path.with_extension("tmp");
    tokio::fs::write(&tmp, compressed)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, loose_path)
        .await
        .with_context(|| format!("installing {}", loose_path.display()))?;
    Ok(())
}

/// The loose path `objects/<oid[0:2]>/<oid[2:]>` for `oid`.
fn loose_object_path(objects_dir: &Path, oid: &str) -> Result<std::path::PathBuf> {
    validate_oid(oid)?;
    Ok(objects_dir.join(&oid[..2]).join(&oid[2..]))
}

/// Validate that `oid` is a 64-character lowercase SHA-256 hex string.
fn validate_oid(oid: &str) -> Result<()> {
    if oid.len() == 64 && oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        bail!("not a valid sha256 object id: {oid:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_oid_accepts_sha256() {
        assert!(validate_oid(&"a".repeat(64)).is_ok());
        assert!(validate_oid(&"0".repeat(40)).is_err()); // sha1 length
        assert!(validate_oid("xyz").is_err());
    }

    #[test]
    fn resolve_refspec_expands_wildcard() {
        let mut advertised = HashMap::new();
        advertised.insert("refs/tags/v1".to_string(), "a".repeat(64));
        advertised.insert("refs/tags/v2".to_string(), "b".repeat(64));
        advertised.insert("refs/heads/main".to_string(), "c".repeat(64));
        let mut out = Vec::new();
        resolve_refspec("refs/tags/*:refs/tags/*", &advertised, None, &mut out).unwrap();
        out.sort();
        assert_eq!(out.len(), 2);
        assert!(out.contains(&("a".repeat(64), Some("refs/tags/v1".to_string()))));
        assert!(out.contains(&("b".repeat(64), Some("refs/tags/v2".to_string()))));
    }

    #[test]
    fn resolve_refspec_head_and_commit() {
        let advertised = HashMap::new();
        let head = "d".repeat(64);
        let mut out = Vec::new();
        resolve_refspec(
            "HEAD:refs/remotes/origin/HEAD",
            &advertised,
            Some(&head),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out,
            vec![(head.clone(), Some("refs/remotes/origin/HEAD".to_string()))]
        );

        let mut out = Vec::new();
        let commit = "e".repeat(64);
        resolve_refspec(&commit, &advertised, None, &mut out).unwrap();
        assert_eq!(out, vec![(commit, None)]);
    }

    #[test]
    fn is_safe_pack_name_rejects_traversal() {
        assert!(is_safe_pack_name("pack-abc123.pack"));
        assert!(!is_safe_pack_name("../evil.pack"));
        assert!(!is_safe_pack_name("pack-/etc/passwd"));
        assert!(!is_safe_pack_name("notapack.pack"));
    }

    /// A static dumb-HTTP test origin over a real SHA-256 repository.
    struct TestOrigin {
        _tmp: tempfile::TempDir,
        url: String,
        head: String,
        /// Count of GETs whose path is under `objects/` (object + pack
        /// downloads), used to assert incremental syncs do no extra work.
        object_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    /// Build a SHA-256 repo (optionally repacked) with a nested subdirectory and
    /// serve its bare `.git` as a static dumb-HTTP tree. Returns `None` when a
    /// loopback socket cannot be bound (sandbox without local TCP).
    fn serve_repo(repack: bool) -> Option<TestOrigin> {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::process::Command;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tmp = tempfile::TempDir::new().unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(work.join("sub")).unwrap();

        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(&work)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        };
        Command::new("git")
            .args(["init", "--object-format=sha256", "-b", "main"])
            .arg(&work)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
            .unwrap();
        git(&["config", "user.email", "a@example.com"]);
        git(&["config", "user.name", "probe"]);
        git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(work.join("file.txt"), b"hello sha256").unwrap();
        std::fs::write(work.join("sub/nested.txt"), b"nested").unwrap();
        git(&["add", "."]);
        git(&["commit", "-m", "init"]);
        if repack {
            // Move every object into a single pack and drop the loose copies,
            // so the reader must use the pack path (objects/info/packs).
            git(&["repack", "-a", "-d"]);
        }
        git(&["update-server-info"]);

        let head = {
            let out = Command::new("git")
                .args(["rev-parse", "main"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        assert_eq!(head.len(), 64, "expected sha256 head, got {head:?}");

        let git_dir = work.join(".git");
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().unwrap();
        let object_requests = Arc::new(AtomicUsize::new(0));
        let counter = object_requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let root = git_dir.clone();
                let counter = counter.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/');
                    if path.starts_with("objects/") {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    match std::fs::read(root.join(path)) {
                        Ok(body) => {
                            let header = format!(
                                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(&body);
                        }
                        Err(_) => {
                            let _ = stream.write_all(
                                b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                    }
                });
            }
        });

        Some(TestOrigin {
            _tmp: tmp,
            url: format!("http://{addr}/"),
            head,
            object_requests,
        })
    }

    const MAIN_REFSPEC: &str = "+refs/heads/main:refs/remotes/origin/main";

    /// Fetch `origin` into a fresh bare client and assert the whole graph landed
    /// (the nested blob reads back) and the ref was set.
    async fn fetch_and_assert(origin: &TestOrigin) -> std::path::PathBuf {
        let client_dir = origin
            ._tmp
            .path()
            .join(format!("client-{}.git", origin.head));
        repo::init_bare_sha256(&client_dir).await.unwrap();
        fetch(&client_dir, &origin.url, &[MAIN_REFSPEC.to_string()])
            .await
            .expect("dumb-http fetch should succeed");
        let resolved = repo::rev_parse(&client_dir, "refs/remotes/origin/main")
            .await
            .unwrap();
        assert_eq!(resolved, origin.head);
        let nested = repo::read_blob_at(&client_dir, &origin.head, "sub/nested.txt")
            .await
            .unwrap();
        assert_eq!(nested.as_deref(), Some(&b"nested"[..]));
        client_dir
    }

    /// End-to-end over the loose-object path (no packs advertised).
    #[tokio::test]
    async fn fetch_reads_static_sha256_repo_loose() {
        let Some(origin) = serve_repo(false) else {
            return;
        };
        fetch_and_assert(&origin).await;
    }

    /// End-to-end over the pack path: a repacked repo serves `objects/info/packs`
    /// and the reader downloads + indexes the pack instead of walking loose.
    #[tokio::test]
    async fn fetch_reads_static_sha256_repo_packed() {
        let Some(origin) = serve_repo(true) else {
            return;
        };
        fetch_and_assert(&origin).await;
    }

    /// A second sync of an unchanged origin must download zero objects/packs —
    /// the local graph already satisfies the targets.
    #[tokio::test]
    async fn fetch_is_incremental() {
        use std::sync::atomic::Ordering;
        let Some(origin) = serve_repo(true) else {
            return;
        };
        let client_dir = origin._tmp.path().join("client.git");
        repo::init_bare_sha256(&client_dir).await.unwrap();

        fetch(&client_dir, &origin.url, &[MAIN_REFSPEC.to_string()])
            .await
            .unwrap();
        let after_first = origin.object_requests.load(Ordering::Relaxed);
        assert!(after_first > 0, "first sync should download objects/packs");

        fetch(&client_dir, &origin.url, &[MAIN_REFSPEC.to_string()])
            .await
            .unwrap();
        let after_second = origin.object_requests.load(Ordering::Relaxed);
        assert_eq!(
            after_second, after_first,
            "an unchanged re-sync must not download any objects or packs"
        );
        assert_eq!(
            repo::rev_parse(&client_dir, "refs/remotes/origin/main")
                .await
                .unwrap(),
            origin.head,
        );
    }
}
