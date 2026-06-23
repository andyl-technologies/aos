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
//! GET <base>/info/refs   ->  "<oid>\t<refname>\n" lines (peeled "^{}" lines
//!                            for annotated tags are ignored; the tag object is
//!                            walked instead)
//! GET <base>/HEAD        ->  "ref: refs/heads/<branch>\n"  (or a bare oid)
//! GET <base>/objects/<oid[0:2]>/<oid[2:]>
//!                        ->  a zlib-compressed loose object:
//!                            inflate -> "<type> <size>\0<body>"
//! ```
//!
//! # Algorithm
//!
//! For each requested refspec the source ref is resolved to an OID via
//! `info/refs`/`HEAD`, then the object graph is walked breadth-first
//! (commit -> tree + parents, tree -> entries, tag -> target). Each object is
//! downloaded, its integrity is verified by recomputing its SHA-256 git OID
//! from the inflated bytes, and the compressed object is written verbatim to
//! the local `objects/<2>/<62>` path. Finally the destination refs are pointed
//! at the resolved OIDs. Object *content* integrity is enforced here by hash;
//! *commit* trust (signatures, fast-forward) is enforced by the caller after
//! the fetch, exactly as for the smart transports.

use std::collections::{HashMap, HashSet, VecDeque};
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

    // Walk and download the object graph reachable from all target OIDs,
    // breadth-first. Each level's objects are fetched concurrently (bounded by
    // MAX_CONCURRENCY) since dumb-HTTP is one round-trip per object; children
    // are only known after a parent is parsed, so concurrency is per-level.
    let objects_dir = repo::objects_dir(repo_dir);
    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: Vec<String> = Vec::new();
    for (oid, _) in &targets {
        if visited.insert(oid.clone()) {
            frontier.push(oid.clone());
        }
    }

    while !frontier.is_empty() {
        if visited.len() > MAX_OBJECTS {
            bail!("registry object graph exceeded {MAX_OBJECTS} objects; refusing to continue");
        }
        let client = &client;
        let objects_dir = &objects_dir;
        let fetched: Vec<(String, Vec<u8>)> = stream::iter(frontier.into_iter())
            .map(|oid| async move {
                let inflated = fetch_one(client, base_url, objects_dir, &oid).await?;
                Ok::<_, anyhow::Error>((oid, inflated))
            })
            .buffer_unordered(MAX_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        let mut next = Vec::new();
        let mut children = VecDeque::new();
        for (oid, inflated) in &fetched {
            children.clear();
            enqueue_referenced_oids(inflated, oid, &mut children)?;
            for child in children.drain(..) {
                if visited.insert(child.clone()) {
                    next.push(child);
                }
            }
        }
        frontier = next;
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

/// Fetch a single object for the graph walk.
///
/// Reads an existing local loose copy (a prior sync) without a round trip;
/// otherwise downloads it, verifies its SHA-256 matches `oid`, and writes the
/// compressed object loose. Returns the inflated `"<type> <size>\0<body>"`
/// bytes for reference discovery.
async fn fetch_one(
    client: &reqwest::Client,
    base_url: &str,
    objects_dir: &Path,
    oid: &str,
) -> Result<Vec<u8>> {
    let loose_path = loose_object_path(objects_dir, oid)?;
    if loose_path.exists() {
        return inflate_loose_file(&loose_path).await;
    }
    let compressed = fetch_object(client, base_url, oid).await?;
    let inflated = inflate(&compressed).with_context(|| format!("inflating object {oid}"))?;
    verify_oid(oid, &inflated)?;
    write_loose_verbatim(&loose_path, &compressed).await?;
    Ok(inflated)
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
    let body = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?
        .text()
        .await
        .with_context(|| format!("reading {url}"))?;

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
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let body = response
        .text()
        .await
        .with_context(|| format!("reading {url}"))?;
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
    let bytes = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching object {oid}"))?
        .error_for_status()
        .with_context(|| format!("fetching object {oid}"))?
        .bytes()
        .await
        .with_context(|| format!("reading object {oid}"))?;
    Ok(bytes.to_vec())
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

/// Read and inflate an existing loose object file.
async fn inflate_loose_file(path: &Path) -> Result<Vec<u8>> {
    let compressed = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    inflate(&compressed)
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

/// Enqueue the OIDs referenced by an inflated object for further walking.
fn enqueue_referenced_oids(inflated: &[u8], oid: &str, queue: &mut VecDeque<String>) -> Result<()> {
    let sep = inflated
        .iter()
        .position(|&b| b == 0)
        .with_context(|| format!("object {oid} has no header NUL"))?;
    let header = std::str::from_utf8(&inflated[..sep])
        .with_context(|| format!("object {oid} has a non-UTF-8 header"))?;
    let kind = header
        .split(' ')
        .next()
        .with_context(|| format!("object {oid} has an empty header"))?;
    let body = &inflated[sep + 1..];
    match kind {
        "commit" => enqueue_commit_refs(body, queue)?,
        "tag" => enqueue_tag_refs(body, queue)?,
        "tree" => enqueue_tree_refs(body, queue)?,
        "blob" => {}
        other => bail!("object {oid} has unknown type {other:?}"),
    }
    Ok(())
}

/// Enqueue the `tree` and `parent` OIDs of a commit object.
fn enqueue_commit_refs(body: &[u8], queue: &mut VecDeque<String>) -> Result<()> {
    let text = std::str::from_utf8(body).context("commit body is not UTF-8")?;
    for line in text.lines() {
        if line.is_empty() {
            break; // header ends at the blank line before the message
        }
        if let Some(oid) = line
            .strip_prefix("tree ")
            .or_else(|| line.strip_prefix("parent "))
        {
            let oid = oid.trim();
            validate_oid(oid)?;
            queue.push_back(oid.to_string());
        }
    }
    Ok(())
}

/// Enqueue the target OID of a tag object.
fn enqueue_tag_refs(body: &[u8], queue: &mut VecDeque<String>) -> Result<()> {
    let text = std::str::from_utf8(body).context("tag body is not UTF-8")?;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(oid) = line.strip_prefix("object ") {
            let oid = oid.trim();
            validate_oid(oid)?;
            queue.push_back(oid.to_string());
        }
    }
    Ok(())
}

/// Enqueue every entry OID of a tree object.
///
/// Tree entries are `"<mode> <name>\0<raw-oid>"` with raw OIDs sized to the
/// repository's hash (32 bytes for SHA-256).
fn enqueue_tree_refs(body: &[u8], queue: &mut VecDeque<String>) -> Result<()> {
    const OID_LEN: usize = 32; // SHA-256 raw length
    let mut i = 0;
    while i < body.len() {
        let nul = body[i..]
            .iter()
            .position(|&b| b == 0)
            .context("tree entry missing NUL")?
            + i;
        let oid_start = nul + 1;
        let oid_end = oid_start + OID_LEN;
        if oid_end > body.len() {
            bail!("tree entry OID truncated");
        }
        queue.push_back(hex::encode(&body[oid_start..oid_end]));
        i = oid_end;
    }
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
    fn enqueue_tree_refs_parses_sha256_entries() {
        let mut body = Vec::new();
        body.extend_from_slice(b"100644 file\0");
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(b"40000 dir\0");
        body.extend_from_slice(&[0x22; 32]);
        let mut queue = VecDeque::new();
        enqueue_tree_refs(&body, &mut queue).unwrap();
        assert_eq!(queue.len(), 2);
        assert_eq!(queue[0], "11".repeat(32));
        assert_eq!(queue[1], "22".repeat(32));
    }

    /// End-to-end: serve a real SHA-256 repository as a static dumb-HTTP tree
    /// and confirm the reader walks the object graph, lands every object, and
    /// sets the destination ref — the production HTTPS transport path.
    #[tokio::test]
    async fn fetch_reads_static_sha256_repo_over_http() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::process::Command;

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
        // A commit whose tree has a nested subdirectory exercises recursive
        // tree walking in the reader.
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

        // Minimal static file server over the bare `.git` directory.
        let git_dir = work.join(".git");
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => return, // loopback bind unavailable; skip
        };
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let root = git_dir.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/');
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

        let url = format!("http://{addr}/");
        let client_dir = tmp.path().join("client.git");
        repo::init_bare_sha256(&client_dir).await.unwrap();
        fetch(
            &client_dir,
            &url,
            &["+refs/heads/main:refs/remotes/origin/main".to_string()],
        )
        .await
        .expect("dumb-http fetch should succeed");

        // The ref was set and the whole graph landed: the commit reads back
        // through git2, including the nested blob.
        let resolved = repo::rev_parse(&client_dir, "refs/remotes/origin/main")
            .await
            .unwrap();
        assert_eq!(resolved, head);
        let nested = repo::read_blob_at(&client_dir, &head, "sub/nested.txt")
            .await
            .unwrap();
        assert_eq!(nested.as_deref(), Some(&b"nested"[..]));
    }
}
