use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use git2::{
    AutotagOption, BranchType, Cred, CredentialType, DiffFormat, DiffOptions, DiffStatsFormat,
    FetchOptions, IndexAddOption, Indexer, ObjectFormat, ObjectType, Oid, PushOptions,
    RemoteCallbacks, Repository, RepositoryInitOptions, Sort, StatusOptions,
};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

const SSH_SIGNATURE_MARKER: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
const SSH_SIGNATURE_NAMESPACE: &str = "git";

/// Open a repository rooted at `path`.
pub fn open(path: &Path) -> Result<Repository> {
    Repository::open(path).with_context(|| format!("opening git repository {}", path.display()))
}

/// Initialize a SHA-256 repository.
pub fn init_sha256(path: &Path, bare: bool, initial_head: &str) -> Result<Repository> {
    let mut opts = RepositoryInitOptions::new();
    opts.bare(bare)
        .mkpath(true)
        .object_format(ObjectFormat::Sha256)
        .initial_head(initial_head)
        .external_template(false);
    Repository::init_opts(path, &opts)
        .with_context(|| format!("initializing SHA-256 git repository {}", path.display()))
}

/// Return the repository's git directory.
pub fn git_dir(repo: &Repository) -> PathBuf {
    repo.path().to_path_buf()
}

/// Assert that a repository uses SHA-256 object ids.
pub fn assert_sha256(repo: &Repository) -> Result<()> {
    let config = repo.config().context("reading git repository config")?;
    let format = config
        .get_string("extensions.objectformat")
        .unwrap_or_else(|_| String::from("sha1"));
    if format != "sha256" {
        bail!("repository uses object format '{format}', expected sha256");
    }
    Ok(())
}

/// Resolve a revspec to an object id.
pub fn resolve_oid(repo: &Repository, revspec: &str) -> Result<Oid> {
    repo.revparse_single(revspec)
        .with_context(|| format!("resolving git revspec '{revspec}'"))
        .map(|object| object.id())
}

/// Resolve a revspec to a commit id.
pub fn resolve_commit_oid(repo: &Repository, revspec: &str) -> Result<Oid> {
    repo.revparse_single(revspec)
        .with_context(|| format!("resolving git commit revspec '{revspec}'"))?
        .peel_to_commit()
        .with_context(|| format!("peeling '{revspec}' to commit"))
        .map(|commit| commit.id())
}

/// Read an object's raw payload bytes.
pub fn raw_object(repo: &Repository, oid_or_rev: &str) -> Result<(ObjectType, Vec<u8>)> {
    let oid = Oid::from_str(oid_or_rev).or_else(|_| resolve_oid(repo, oid_or_rev))?;
    let odb = repo.odb().context("opening git object database")?;
    let object = odb
        .read(oid)
        .with_context(|| format!("reading git object {oid}"))?;
    Ok((object.kind(), object.data().to_vec()))
}

/// Write a tag object payload to the object database and return its id.
pub fn write_tag_object(repo: &Repository, bytes: &[u8]) -> Result<Oid> {
    repo.odb()
        .context("opening git object database")?
        .write(ObjectType::Tag, bytes)
        .context("writing tag object")
}

/// Fetch refspecs from `url` into the repository at `repo_dir`.
pub fn fetch(repo_dir: &Path, url: &str, refspecs: &[String]) -> Result<()> {
    let repo = open(repo_dir)?;
    let mut remote = repo.remote_anonymous(url)?;
    let mut options = FetchOptions::new();
    options
        .remote_callbacks(remote_callbacks(&repo)?)
        .download_tags(AutotagOption::All)
        .update_fetchhead(true);
    let refspec_refs: Vec<&str> = refspecs.iter().map(String::as_str).collect();
    remote
        .fetch(&refspec_refs, Some(&mut options), None)
        .with_context(|| format!("fetching {} from {url}", refspecs.join(" ")))
}

/// Push refspecs to a named remote.
pub fn push(repo: &Repository, remote_name: &str, refspecs: &[String]) -> Result<()> {
    let mut remote = repo
        .find_remote(remote_name)
        .with_context(|| format!("opening remote '{remote_name}'"))?;
    let mut options = PushOptions::new();
    options.remote_callbacks(remote_callbacks(repo)?);
    let refs: Vec<&str> = refspecs.iter().map(String::as_str).collect();
    remote
        .push(&refs, Some(&mut options))
        .with_context(|| format!("pushing {} to {remote_name}", refspecs.join(" ")))
}

/// Return true when `ancestor` is reachable from `descendant`.
pub fn is_ancestor(repo: &Repository, ancestor: &str, descendant: &str) -> Result<bool> {
    let ancestor = resolve_commit_oid(repo, ancestor)?;
    let descendant = resolve_commit_oid(repo, descendant)?;
    repo.graph_descendant_of(descendant, ancestor)
        .context("checking git commit ancestry")
}

/// Return semver-looking tag names as raw tag strings.
pub fn tag_names(repo: &Repository) -> Result<Vec<String>> {
    let names = repo.tag_names(None).context("listing git tags")?;
    let mut tags: Vec<String> = names
        .iter()
        .filter_map(|name| name.ok().flatten().map(ToString::to_string))
        .collect();
    tags.sort();
    Ok(tags)
}

/// Extract `prefix` from `commit` into `output_dir`.
pub fn extract_tree_prefix(
    repo: &Repository,
    commit: &str,
    prefix: &Path,
    output_dir: &Path,
) -> Result<()> {
    if output_dir.exists() {
        fs::remove_dir_all(output_dir)
            .with_context(|| format!("cleaning {}", output_dir.display()))?;
    }
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;

    let commit = repo
        .find_commit(resolve_commit_oid(repo, commit)?)
        .context("loading commit for tree extraction")?;
    let tree = commit.tree().context("loading commit tree")?;
    let entry = match tree.get_path(prefix) {
        Ok(entry) => entry,
        Err(err) if err.code() == git2::ErrorCode::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("reading tree path {}", prefix.display()));
        }
    };
    let subtree = repo
        .find_tree(entry.id())
        .with_context(|| format!("loading tree {}", prefix.display()))?;
    write_tree(repo, &subtree, output_dir)
}

/// Read a blob at `path` from a commit tree.
pub fn read_blob_at(repo: &Repository, commit: &str, path: &Path) -> Result<Option<Vec<u8>>> {
    let commit = repo
        .find_commit(resolve_commit_oid(repo, commit)?)
        .context("loading commit for blob read")?;
    let tree = commit.tree().context("loading commit tree")?;
    let entry = match tree.get_path(path) {
        Ok(entry) => entry,
        Err(err) if err.code() == git2::ErrorCode::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("reading tree path {}", path.display()));
        }
    };
    if entry.kind() != Some(ObjectType::Blob) {
        return Ok(None);
    }
    let blob = repo
        .find_blob(entry.id())
        .with_context(|| format!("loading blob {}", path.display()))?;
    Ok(Some(blob.content().to_vec()))
}

/// Write a full pack containing everything reachable from `commit`.
pub fn write_full_pack(repo: &Repository, commit: &str, out_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let oid = resolve_commit_oid(repo, commit)?;
    let mut builder = repo.packbuilder().context("creating git pack builder")?;
    builder.set_threads(0);
    builder
        .insert_commit(oid)
        .with_context(|| format!("inserting commit {oid} into pack"))?;
    builder
        .write(out_dir, 0)
        .with_context(|| format!("writing pack into {}", out_dir.display()))?;
    let name = builder
        .name()
        .context("reading git pack name")?
        .ok_or_else(|| anyhow::anyhow!("git pack builder did not report a pack name"))?;
    Ok(out_dir.join(format!("pack-{name}.pack")))
}

/// Write a self-contained delta pack for `to_commit`, hiding `from_commit`.
pub fn write_delta_pack(
    repo: &Repository,
    from_commit: &str,
    to_commit: &str,
    out: &Path,
) -> Result<()> {
    let from = resolve_commit_oid(repo, from_commit)?;
    let to = resolve_commit_oid(repo, to_commit)?;
    let mut walk = repo.revwalk().context("creating git revwalk")?;
    walk.push(to)
        .with_context(|| format!("adding {to} to pack revwalk"))?;
    walk.hide(from)
        .with_context(|| format!("hiding {from} from pack revwalk"))?;

    let mut builder = repo.packbuilder().context("creating git pack builder")?;
    builder.set_threads(0);
    builder
        .insert_walk(&mut walk)
        .context("inserting revwalk into pack")?;
    let mut bytes = Vec::new();
    builder
        .foreach(|chunk| {
            bytes.extend_from_slice(chunk);
            true
        })
        .context("writing pack bytes")?;
    fs::write(out, bytes).with_context(|| format!("writing {}", out.display()))
}

/// Index a pack file into `repo`.
pub fn index_pack(repo: &Repository, pack: &Path) -> Result<()> {
    let pack_dir = pack
        .parent()
        .ok_or_else(|| anyhow::anyhow!("pack has no parent directory: {}", pack.display()))?;
    let bytes = fs::read(pack).with_context(|| format!("reading {}", pack.display()))?;
    let odb = repo.odb().context("opening git object database")?;
    let mut indexer = Indexer::new_ext(Some(&odb), pack_dir, 0, true, ObjectFormat::Sha256)
        .with_context(|| format!("creating pack indexer for {}", pack_dir.display()))?;
    indexer
        .write_all(&bytes)
        .with_context(|| format!("indexing {}", pack.display()))?;
    indexer.commit().context("committing pack index")?;
    Ok(())
}

/// Write dumb-HTTP metadata files for a repository.
pub fn refresh_server_info(repo: &Repository) -> Result<()> {
    let git_dir = git_dir(repo);
    write_info_refs(repo, &git_dir)?;
    write_info_packs(&git_dir.join("objects").join("pack"))?;
    write_release_info_packs(&git_dir.join("releases"))?;
    Ok(())
}

/// Ensure reachable objects have loose-object files under the root object dir.
pub fn ensure_loose_objects(repo: &Repository) -> Result<()> {
    let git_dir = git_dir(repo);
    let odb = repo.odb().context("opening git object database")?;
    let mut refs = repo.references().context("listing git refs")?;
    for reference in &mut refs {
        let reference = reference.context("reading git ref")?;
        let Some(oid) = reference
            .target()
            .or_else(|| reference.resolve().ok()?.target())
        else {
            continue;
        };
        write_loose_object(&git_dir, &odb.read(oid)?)?;
    }

    let mut walk = repo.revwalk().context("creating git revwalk")?;
    walk.push_glob("refs/*").context("walking git refs")?;
    for oid in walk {
        let oid = oid.context("walking commit")?;
        write_loose_object(&git_dir, &odb.read(oid)?)?;
        let commit = repo
            .find_commit(oid)
            .with_context(|| format!("loading commit {oid}"))?;
        write_tree_loose(&git_dir, repo, &commit.tree()?)?;
    }
    Ok(())
}

/// Commit every staged and unstaged change in a worktree.
pub fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index().context("opening git index")?;
    index
        .add_all(["*"], IndexAddOption::DEFAULT, None)
        .context("adding registry changes to git index")?;
    index.write().context("writing git index")?;
    let tree_id = index.write_tree().context("writing git tree")?;
    let tree = repo
        .find_tree(tree_id)
        .context("loading written git tree")?;
    let signature = repo.signature().context("reading git user signature")?;
    let parents = match repo.head() {
        Ok(head) => {
            let parent = head
                .peel_to_commit()
                .context("peeling HEAD to parent commit")?;
            vec![parent]
        }
        Err(err) if err.code() == git2::ErrorCode::UnbornBranch => Vec::new(),
        Err(err) if err.code() == git2::ErrorCode::NotFound => Vec::new(),
        Err(err) => return Err(err).context("reading HEAD for commit"),
    };
    let parent_refs: Vec<_> = parents.iter().collect();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parent_refs,
    )
    .with_context(|| format!("creating git commit '{message}'"))
}

/// Create or replace an SSH-signed tag object.
pub fn sign_tag(
    repo: &Repository,
    tag_name: &str,
    target: &str,
    message: &str,
    signing_key: &Path,
    force: bool,
) -> Result<Oid> {
    let target = repo
        .revparse_single(target)
        .with_context(|| format!("resolving tag target '{target}'"))?;
    let target_type = target
        .kind()
        .ok_or_else(|| anyhow::anyhow!("target '{}' has no git object type", target.id()))?;
    let tagger = repo.signature().context("reading git tagger signature")?;
    let mut payload = String::new();
    payload.push_str(&format!("object {}\n", target.id()));
    payload.push_str(&format!("type {}\n", object_type_name(target_type)?));
    payload.push_str(&format!("tag {tag_name}\n"));
    payload.push_str(&format!("tagger {}\n", format_signature(&tagger)));
    payload.push('\n');
    payload.push_str(message);
    if !message.ends_with('\n') {
        payload.push('\n');
    }

    let private_key = PrivateKey::read_openssh_file(signing_key)
        .with_context(|| format!("reading SSH signing key {}", signing_key.display()))?;
    let signature = private_key
        .sign(SSH_SIGNATURE_NAMESPACE, HashAlg::Sha512, payload.as_bytes())
        .context("creating SSH signature for tag object")?;
    let signature = signature
        .to_pem(LineEnding::LF)
        .context("encoding SSH signature")?;

    let mut tag_object = payload.into_bytes();
    tag_object.extend_from_slice(signature.as_bytes());
    let oid = write_tag_object(repo, &tag_object)?;
    repo.reference(
        &format!("refs/tags/{tag_name}"),
        oid,
        force,
        &format!("tag: {tag_name}"),
    )
    .with_context(|| format!("updating refs/tags/{tag_name}"))?;
    Ok(oid)
}

/// Delete a tag reference.
pub fn delete_tag(repo: &Repository, name: &str) -> Result<()> {
    repo.tag_delete(name)
        .with_context(|| format!("deleting tag '{name}'"))
}

/// Verify an SSH signature on a commit.
pub fn verify_commit_signature(
    repo: &Repository,
    commit: &str,
    expected_key: &str,
) -> Result<bool> {
    let oid = resolve_commit_oid(repo, commit)?;
    let (signature, signed_data) = match repo.extract_signature(&oid, None) {
        Ok(parts) => parts,
        Err(err) if err.code() == git2::ErrorCode::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("extracting signature from {oid}")),
    };
    verify_ssh_signature(expected_key, signed_data.as_ref(), signature.as_ref())
}

/// Verify an SSH signature on a tag object or tag ref.
pub fn verify_tag_signature(repo: &Repository, tag: &str, expected_key: &str) -> Result<bool> {
    let (_kind, data) = raw_object(repo, tag)?;
    let Some(marker) = find_subslice(&data, SSH_SIGNATURE_MARKER) else {
        return Ok(false);
    };
    let signed_data = &data[..marker];
    let signature = &data[marker..];
    verify_ssh_signature(expected_key, signed_data, signature)
}

fn remote_callbacks(repo: &Repository) -> Result<RemoteCallbacks<'_>> {
    let config = repo.config().context("reading git config")?;
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(move |url, username_from_url, allowed| {
        if allowed.contains(CredentialType::SSH_KEY) {
            if let Some(username) = username_from_url {
                if let Ok(cred) = Cred::ssh_key_from_agent(username) {
                    return Ok(cred);
                }
            }
        }
        if allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
            if let Ok(cred) = Cred::credential_helper(&config, url, username_from_url) {
                return Ok(cred);
            }
        }
        if allowed.contains(CredentialType::USERNAME) {
            if let Some(username) = username_from_url {
                return Cred::username(username);
            }
        }
        Cred::default()
    });
    Ok(callbacks)
}

fn write_tree(repo: &Repository, tree: &git2::Tree<'_>, output_dir: &Path) -> Result<()> {
    for entry in tree {
        let name = entry.name().context("reading tree entry name")?;
        let path = output_dir.join(name);
        match entry.kind() {
            Some(ObjectType::Blob) => {
                let blob = repo
                    .find_blob(entry.id())
                    .with_context(|| format!("loading blob {}", entry.id()))?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                fs::write(&path, blob.content())
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            Some(ObjectType::Tree) => {
                fs::create_dir_all(&path)
                    .with_context(|| format!("creating {}", path.display()))?;
                let subtree = repo
                    .find_tree(entry.id())
                    .with_context(|| format!("loading tree {}", entry.id()))?;
                write_tree(repo, &subtree, &path)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn write_info_refs(repo: &Repository, git_dir: &Path) -> Result<()> {
    let mut rows = Vec::new();
    let refs = repo.references().context("listing git refs")?;
    for reference in refs {
        let reference = reference.context("reading git ref")?;
        let name = reference.name().context("reading ref name")?;
        if name.ends_with("^{}") {
            continue;
        }
        let Some(oid) = reference
            .target()
            .or_else(|| reference.resolve().ok()?.target())
        else {
            continue;
        };
        rows.push(format!("{oid}\t{name}\n"));
        if name.starts_with("refs/tags/") {
            if let Ok(commit) = reference.peel_to_commit() {
                if commit.id() != oid {
                    rows.push(format!("{}\t{}^{{}}\n", commit.id(), name));
                }
            }
        }
    }
    rows.sort();
    fs::write(git_dir.join("info").join("refs"), rows.concat())
        .with_context(|| format!("writing {}", git_dir.join("info/refs").display()))
}

fn write_info_packs(pack_dir: &Path) -> Result<()> {
    let info_dir = pack_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("pack dir has no parent: {}", pack_dir.display()))?
        .join("info");
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;
    let mut packs = Vec::new();
    if pack_dir.exists() {
        for entry in
            fs::read_dir(pack_dir).with_context(|| format!("reading {}", pack_dir.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("pack-") && name.ends_with(".pack") {
                packs.push(format!("P {name}\n"));
            }
        }
    }
    packs.sort();
    fs::write(info_dir.join("packs"), packs.concat())
        .with_context(|| format!("writing {}", info_dir.join("packs").display()))
}

fn write_release_info_packs(releases: &Path) -> Result<()> {
    if !releases.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(releases).with_context(|| format!("reading {}", releases.display()))?
    {
        let path = entry?.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("pack") {
            write_info_packs(&path)?;
        } else if path.is_dir() {
            write_release_info_packs(&path)?;
        }
    }
    Ok(())
}

fn write_tree_loose(git_dir: &Path, repo: &Repository, tree: &git2::Tree<'_>) -> Result<()> {
    let odb = repo.odb().context("opening git object database")?;
    let tree_object = odb.read(tree.id())?;
    write_loose_object(git_dir, &tree_object)?;
    for entry in tree {
        match entry.kind() {
            Some(ObjectType::Blob) => {
                let object = odb.read(entry.id())?;
                write_loose_object(git_dir, &object)?;
            }
            Some(ObjectType::Tree) => {
                let subtree = repo.find_tree(entry.id())?;
                write_tree_loose(git_dir, repo, &subtree)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn write_loose_object(git_dir: &Path, object: &git2::OdbObject<'_>) -> Result<()> {
    let oid = object.id().to_string();
    let dir = git_dir.join("objects").join(&oid[..2]);
    let path = dir.join(&oid[2..]);
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut plain = Vec::new();
    plain.extend_from_slice(object_type_name(object.kind())?.as_bytes());
    plain.push(b' ');
    plain.extend_from_slice(object.len().to_string().as_bytes());
    plain.push(0);
    plain.extend_from_slice(object.data());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&plain)
        .context("compressing loose object")?;
    let compressed = encoder.finish().context("finishing loose object")?;
    fs::write(&path, compressed).with_context(|| format!("writing {}", path.display()))
}

fn verify_ssh_signature(expected_key: &str, signed_data: &[u8], signature: &[u8]) -> Result<bool> {
    let (_registry, _algorithm, public_key) = crate::security::parse_signing_key(expected_key)?;
    let public_key = PublicKey::from_openssh(&format!("ssh-ed25519 {public_key} registry"))
        .context("parsing trusted SSH public key")?;
    let signature = SshSig::from_pem(signature).context("parsing SSH signature")?;
    Ok(public_key
        .verify(SSH_SIGNATURE_NAMESPACE, signed_data, &signature)
        .is_ok())
}

fn format_signature(signature: &git2::Signature<'_>) -> String {
    let name = String::from_utf8_lossy(signature.name_bytes());
    let email = String::from_utf8_lossy(signature.email_bytes());
    let time = signature.when();
    let offset = time.offset_minutes();
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.abs();
    let hours = offset / 60;
    let minutes = offset % 60;
    format!(
        "{name} <{email}> {} {sign}{hours:02}{minutes:02}",
        time.seconds()
    )
}

fn object_type_name(kind: ObjectType) -> Result<&'static str> {
    match kind {
        ObjectType::Any => bail!("unsupported git object type 'any'"),
        ObjectType::Commit => Ok("commit"),
        ObjectType::Tree => Ok("tree"),
        ObjectType::Blob => Ok("blob"),
        ObjectType::Tag => Ok("tag"),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Render a short status summary for porcelain commands.
pub fn status(repo: &Repository) -> Result<String> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut opts))
        .context("reading git status")?;
    if statuses.is_empty() {
        return Ok(String::from(
            "On branch clean\nnothing to commit, working tree clean",
        ));
    }
    let mut out = String::from("Changes:\n");
    for entry in statuses.iter() {
        let path = entry.path().context("reading status path")?;
        out.push_str("  ");
        out.push_str(path);
        out.push('\n');
    }
    Ok(out)
}

/// Render a diff for either the worktree or two revspecs.
pub fn diff(
    repo: &Repository,
    left: Option<&str>,
    right: Option<&str>,
    stat: bool,
) -> Result<String> {
    let mut options = DiffOptions::new();
    let diff = match (left, right) {
        (Some(left), Some(right)) => {
            let left = repo.find_commit(resolve_commit_oid(repo, left)?)?.tree()?;
            let right = repo.find_commit(resolve_commit_oid(repo, right)?)?.tree()?;
            repo.diff_tree_to_tree(Some(&left), Some(&right), Some(&mut options))?
        }
        _ => {
            let head = repo.head().ok().and_then(|head| head.peel_to_tree().ok());
            repo.diff_tree_to_workdir_with_index(head.as_ref(), Some(&mut options))?
        }
    };
    if stat {
        let stats = diff.stats().context("building diff stats")?;
        let buf = stats
            .to_buf(DiffStatsFormat::FULL, 80)
            .context("formatting diff stats")?;
        return Ok(String::from_utf8_lossy(buf.as_ref()).to_string());
    }
    let mut bytes = Vec::new();
    diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        bytes.extend_from_slice(line.content());
        true
    })
    .context("formatting diff")?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Render an oneline log from HEAD.
pub fn log(repo: &Repository, max: usize, path_filter: Option<&Path>) -> Result<String> {
    let mut walk = repo.revwalk().context("creating git revwalk")?;
    walk.push_head().context("walking HEAD")?;
    walk.set_sorting(Sort::TIME)?;
    let mut out = String::new();
    for oid in walk.take(max) {
        let oid = oid.context("walking git history")?;
        let commit = repo.find_commit(oid)?;
        if let Some(path) = path_filter {
            if !commit_touches_path(repo, &commit, path)? {
                continue;
            }
        }
        let short = oid.to_string();
        out.push_str(&short[..12.min(short.len())]);
        out.push(' ');
        out.push_str(commit.summary().ok().flatten().unwrap_or("(no summary)"));
        out.push('\n');
    }
    Ok(out.trim_end().to_string())
}

fn commit_touches_path(repo: &Repository, commit: &git2::Commit<'_>, path: &Path) -> Result<bool> {
    let tree = commit.tree()?;
    let parent_tree = if commit.parent_count() > 0 {
        Some(commit.parent(0)?.tree()?)
    } else {
        None
    };
    let mut options = DiffOptions::new();
    options.pathspec(path);
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut options))?;
    Ok(diff.deltas().len() > 0)
}

/// List local and remote branches.
pub fn branch_list(repo: &Repository) -> Result<String> {
    let mut out = String::new();
    for branch in repo.branches(None).context("listing branches")? {
        let (branch, kind) = branch?;
        let marker = if branch.is_head() { "* " } else { "  " };
        let prefix = if kind == BranchType::Remote {
            "remotes/"
        } else {
            ""
        };
        if let Some(name) = branch.name()? {
            out.push_str(marker);
            out.push_str(prefix);
            out.push_str(name);
            out.push('\n');
        }
    }
    Ok(out.trim_end().to_string())
}

/// Create a local branch at HEAD.
pub fn branch_create(repo: &Repository, name: &str) -> Result<()> {
    let head = repo.head()?.peel_to_commit()?;
    repo.branch(name, &head, false)
        .with_context(|| format!("creating branch '{name}'"))?;
    Ok(())
}

/// Switch to a local branch and update the worktree.
pub fn checkout_branch(repo: &Repository, name: &str) -> Result<()> {
    repo.set_head(&format!("refs/heads/{name}"))
        .with_context(|| format!("switching to branch '{name}'"))?;
    repo.checkout_head(None)
        .with_context(|| format!("checking out branch '{name}'"))
}

/// Delete a local branch.
pub fn branch_delete(repo: &Repository, name: &str) -> Result<()> {
    let mut branch = repo
        .find_branch(name, BranchType::Local)
        .with_context(|| format!("finding branch '{name}'"))?;
    branch
        .delete()
        .with_context(|| format!("deleting branch '{name}'"))
}

/// Add a named remote.
pub fn remote_add(repo: &Repository, name: &str, url: &str) -> Result<()> {
    repo.remote(name, url)
        .with_context(|| format!("adding remote '{name}'"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::private::Ed25519Keypair;

    #[test]
    fn signs_and_verifies_ssh_tag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("repo");
        let repo = init_sha256(&repo_dir, false, "stable").unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.email", "aos@example.invalid").unwrap();
        config.set_str("user.name", "AOS Test").unwrap();

        fs::write(
            repo_dir.join("registry.toml"),
            "[registry]\nname = \"test\"\n",
        )
        .unwrap();
        let commit = commit_all(&repo, "init").unwrap();

        let private_key: PrivateKey = Ed25519Keypair::from_seed(&[42; 32]).into();
        let public_key = private_key.public_key().to_openssh().unwrap();
        let public_key = public_key
            .split_whitespace()
            .nth(1)
            .expect("OpenSSH public key should include base64 key data");
        let key_path = tmp.path().join("signing-key");
        private_key
            .write_openssh_file(&key_path, LineEnding::LF)
            .unwrap();

        sign_tag(
            &repo,
            "1.0.0",
            &commit.to_string(),
            "release",
            &key_path,
            false,
        )
        .unwrap();
        assert!(
            verify_tag_signature(&repo, "1.0.0", &format!("test:Ed25519:{public_key}")).unwrap()
        );

        let other_private_key: PrivateKey = Ed25519Keypair::from_seed(&[7; 32]).into();
        let other_public_key = other_private_key.public_key().to_openssh().unwrap();
        let other_public_key = other_public_key
            .split_whitespace()
            .nth(1)
            .expect("OpenSSH public key should include base64 key data");
        assert!(
            !verify_tag_signature(&repo, "1.0.0", &format!("test:Ed25519:{other_public_key}"))
                .unwrap()
        );
    }
}
