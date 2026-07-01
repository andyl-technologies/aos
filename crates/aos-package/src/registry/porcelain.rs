//! libgit2 reimplementation of the git porcelain that `apr` shells out to.
//!
//! `registry_ops` drives an authoring registry through a small `git()` helper
//! that runs a git subcommand and returns its stdout. This module reimplements
//! that subcommand surface on libgit2 so the registry tooling carries no
//! dependency on the `git` CLI. [`dispatch`] matches the exact argument shapes
//! used by the callers and returns the same stdout bytes (and the same
//! success/failure semantics) the CLI would, so the call sites are unchanged.
//!
//! Only the subcommands `apr` actually invokes are handled; an unrecognized
//! invocation is a programming error and returns `Err`. Expected git-level
//! failures (a missing ref or object) return [`Output`] with `success = false`,
//! matching a non-zero CLI exit.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use git2::{Repository, Status};

/// The captured result of a reimplemented git subcommand.
pub(crate) struct Output {
    /// Whether the command "succeeded" (CLI exit status zero).
    pub success: bool,
    /// Captured standard output bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error text (only meaningful when `!success`).
    pub stderr: String,
}

impl Output {
    /// A successful result carrying `stdout`.
    fn ok(stdout: Vec<u8>) -> Self {
        Self {
            success: true,
            stdout,
            stderr: String::new(),
        }
    }

    /// A successful result carrying UTF-8 `stdout`.
    fn ok_str(stdout: impl Into<String>) -> Self {
        Self::ok(stdout.into().into_bytes())
    }

    /// A failed result (non-zero exit) carrying `stderr`.
    fn fail(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }
}

/// Open the repository at `dir` (or any parent), matching git's discovery.
fn open(dir: &Path) -> Result<Repository> {
    Repository::open(dir)
        .or_else(|_| Repository::discover(dir))
        .with_context(|| format!("opening git repository at {}", dir.display()))
}

/// Reimplement `git <args>` run in `dir` using libgit2.
///
/// # Errors
///
/// Returns an error only for an unsupported invocation or an unexpected
/// libgit2 failure; ordinary git-level failures (missing ref/object) are
/// reported through [`Output::success`].
pub(crate) fn dispatch(dir: &Path, args: &[&str]) -> Result<Output> {
    match args {
        ["init", rest @ ..] => init(dir, rest),
        ["ls-tree", rest @ ..] => ls_tree(dir, rest),
        ["symbolic-ref", "HEAD", target] => {
            open(dir)?.set_head(target).context("setting HEAD")?;
            Ok(Output::ok_str(""))
        }
        ["rev-parse", rest @ ..] => rev_parse(dir, rest),
        ["rev-list", rest @ ..] => rev_list(dir, rest),
        ["merge-base", "--is-ancestor", ancestor, descendant] => {
            merge_base_is_ancestor(dir, ancestor, descendant)
        }
        ["for-each-ref", rest @ ..] => for_each_ref(dir, rest),
        ["cat-file", "-e", spec] => Ok(match resolve_blob_bytes(&open(dir)?, spec)? {
            Some(_) => Output::ok_str(""),
            None => Output::fail(format!("{spec} does not exist")),
        }),
        ["cat-file", "-p", spec] | ["show", spec] => cat_file_p(dir, spec),
        ["config", key] => config_get(dir, key),
        ["config", key, value] => config_set(dir, key, value),
        ["add", rest @ ..] => add(dir, rest),
        ["commit", "-m", message] => commit_unsigned(dir, message),
        ["tag", "--list"] => tag_list(dir),
        ["tag", "-d", name] => tag_delete(dir, name),
        ["remote"] => remotes(dir),
        ["remote", "get-url", name] => remote_url(dir, name),
        ["remote", "add", name, url] => {
            open(dir)?
                .remote(name, url)
                .with_context(|| format!("adding remote {name}"))?;
            Ok(Output::ok_str(""))
        }
        ["update-ref", name, oid] => update_ref(dir, name, oid),
        ["read-tree", "-u", "--reset", treeish] => read_tree_reset(dir, treeish),
        ["status", rest @ ..] => status(dir, rest),
        ["ls-files", rest @ ..] => ls_files(dir, rest),
        ["diff", rest @ ..] => diff(dir, rest),
        ["log", rest @ ..] => log(dir, rest),
        ["branch", rest @ ..] => branch(dir, rest),
        ["switch", rest @ ..] => switch(dir, rest),
        ["merge", rest @ ..] => merge(dir, rest),
        ["push", rest @ ..] => push(dir, rest),
        ["pull", rest @ ..] => pull(dir, rest),
        ["fetch", rest @ ..] => fetch(dir, rest),
        _ => bail!("unsupported git invocation: git {}", args.join(" ")),
    }
}

/// `git init [--bare] [--object-format=sha256] [--initial-branch=<name>] [<dir>]`.
fn init(dir: &Path, rest: &[&str]) -> Result<Output> {
    let mut opts = git2::RepositoryInitOptions::new();
    opts.bare(rest.contains(&"--bare"));
    if rest.iter().any(|a| *a == "--object-format=sha256") {
        opts.object_format(git2::ObjectFormat::Sha256);
    }
    if let Some(branch) = rest
        .iter()
        .find_map(|a| a.strip_prefix("--initial-branch="))
    {
        opts.initial_head(&format!("refs/heads/{branch}"));
    }
    // An optional positional directory argument selects where to init.
    let target = match rest.iter().find(|a| !a.starts_with('-')) {
        Some(path) => dir.join(path),
        None => dir.to_path_buf(),
    };
    Repository::init_opts(&target, &opts)
        .with_context(|| format!("git init in {}", target.display()))?;
    Ok(Output::ok_str(""))
}

/// `git ls-tree -r --name-only <treeish> -- <pathspec>`: list blob paths under
/// `treeish` (recursively) whose path begins with `pathspec`.
fn ls_tree(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let positional = rest
        .iter()
        .copied()
        .find(|a| !a.starts_with('-') && *a != "--");
    let Some(treeish) = positional else {
        bail!("git ls-tree requires a tree-ish");
    };
    let pathspec = rest
        .iter()
        .position(|a| *a == "--")
        .and_then(|i| rest.get(i + 1))
        .copied();

    let tree = match repo.revparse_single(treeish) {
        Ok(object) => object
            .peel_to_tree()
            .with_context(|| format!("{treeish} has no tree"))?,
        Err(e) => return Ok(Output::fail(e.message().to_string())),
    };
    let mut paths = Vec::new();
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob)
            && let Ok(name) = entry.name()
        {
            paths.push(format!("{root}{name}"));
        }
        git2::TreeWalkResult::Ok
    })
    .context("walking tree")?;

    let mut out = String::new();
    for path in paths {
        if pathspec.is_none_or(|spec| path.starts_with(spec)) {
            let _ = writeln!(out, "{path}");
        }
    }
    Ok(Output::ok_str(out))
}

/// `git rev-parse <...>`.
fn rev_parse(dir: &Path, rest: &[&str]) -> Result<Output> {
    // Outside a repository git exits non-zero rather than erroring hard, which
    // callers probe (e.g. `--is-inside-work-tree`) via the fallible helper.
    let repo = match open(dir) {
        Ok(repo) => repo,
        Err(e) => return Ok(Output::fail(e.to_string())),
    };
    match rest {
        ["--is-inside-work-tree"] => Ok(Output::ok_str(if repo.is_bare() {
            "false"
        } else {
            "true"
        })),
        ["--is-bare-repository"] => Ok(Output::ok_str(if repo.is_bare() {
            "true"
        } else {
            "false"
        })),
        ["--abbrev-ref", "HEAD"] => match repo.head() {
            Ok(head) => Ok(Output::ok_str(
                head.shorthand().unwrap_or("HEAD").to_string(),
            )),
            Err(_) => Ok(Output::ok_str("HEAD")),
        },
        ["--abbrev-ref", "--symbolic-full-name", "@{upstream}"]
        | ["--abbrev-ref", "@{upstream}"] => match upstream_shorthand(&repo) {
            Some(name) => Ok(Output::ok_str(name)),
            None => Ok(Output::fail(
                "no upstream configured for the current branch",
            )),
        },
        ["--verify", spec] | [spec] => match repo.revparse_single(spec) {
            Ok(object) => Ok(Output::ok_str(object.id().to_string())),
            Err(e) => Ok(Output::fail(e.message().to_string())),
        },
        _ => bail!("unsupported git rev-parse {}", rest.join(" ")),
    }
}

/// Short name (`origin/main`) of the current branch's upstream, if configured.
fn upstream_shorthand(repo: &Repository) -> Option<String> {
    let head = repo.head().ok()?;
    if !head.is_branch() {
        return None;
    }
    let branch = git2::Branch::wrap(head);
    let upstream = branch.upstream().ok()?;
    upstream.name().ok().flatten().map(ToString::to_string)
}

/// `git rev-list [-n N] <spec>` and `git rev-list --count --branches --not
/// --remotes` (the count of commits on local branches not on any remote).
fn rev_list(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    if rest.contains(&"--count") && rest.contains(&"--branches") && rest.contains(&"--remotes") {
        return rev_list_unpushed_count(&repo);
    }
    // Supported forms: ["-n", "1", spec] and [spec].
    let (limit, spec) = match rest {
        ["-n", n, spec] => (Some(n.parse::<usize>().unwrap_or(1)), *spec),
        [spec] => (None, *spec),
        _ => bail!("unsupported git rev-list {}", rest.join(" ")),
    };
    let start = match repo.revparse_single(spec) {
        Ok(object) => object,
        Err(e) => return Ok(Output::fail(e.message().to_string())),
    };
    let commit = start
        .peel_to_commit()
        .context("rev-list start is not a commit")?;
    let mut walk = repo.revwalk().context("creating revwalk")?;
    walk.push(commit.id()).context("seeding revwalk")?;
    let mut out = String::new();
    for (i, oid) in walk.enumerate() {
        if limit.is_some_and(|l| i >= l) {
            break;
        }
        let _ = writeln!(out, "{}", oid?);
    }
    Ok(Output::ok_str(out))
}

/// Count commits reachable from any local branch but from no remote-tracking
/// branch — i.e. commits not yet pushed anywhere.
fn rev_list_unpushed_count(repo: &Repository) -> Result<Output> {
    let mut walk = repo.revwalk().context("creating revwalk")?;
    for item in repo
        .branches(Some(git2::BranchType::Local))
        .context("listing branches")?
    {
        let (b, _) = item?;
        if let Some(oid) = b.get().target() {
            let _ = walk.push(oid);
        }
    }
    for reference in repo
        .references_glob("refs/remotes/**")
        .context("listing remotes")?
    {
        if let Some(oid) = reference?.target() {
            let _ = walk.hide(oid);
        }
    }
    let count = walk.filter_map(std::result::Result::ok).count();
    Ok(Output::ok_str(count.to_string()))
}

/// `git for-each-ref --format=<fmt> <pattern>...`.
///
/// Expands the `--format` string over every ref under the given `refs/...`
/// prefix patterns, one line per matching ref, sorted ascending by full
/// refname and each terminated by a newline (matching git). The supported
/// placeholders cover what `apr` requests: `%(refname)`, `%(refname:short)`,
/// `%(objectname)` (symbolic refs are followed to their target),
/// `%(contents:subject)` (the first line of the pointed-to commit/tag message),
/// and the escapes `%00` (NUL) and `%09` (tab). When no `--format` is given,
/// git's default `%(objectname) %(refname)` is used.
///
/// # Errors
///
/// Returns an error if the repository cannot be opened or its refs listed.
fn for_each_ref(dir: &Path, rest: &[&str]) -> Result<Output> {
    let format = rest
        .iter()
        .copied()
        .find_map(|arg| arg.strip_prefix("--format="))
        .unwrap_or("%(objectname) %(refname)");
    let patterns: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    let repo = open(dir)?;
    let want_subject = format.contains("%(contents:subject)");
    let mut rows: Vec<(String, String)> = Vec::new();
    for reference in repo.references().context("listing references")? {
        let reference = reference?;
        let Ok(name) = reference.name() else {
            continue;
        };
        let under_pattern = patterns
            .iter()
            .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}/")));
        if !under_pattern {
            continue;
        }
        let Some(oid) = reference
            .target()
            .or_else(|| reference.resolve().ok().and_then(|r| r.target()))
        else {
            continue; // unresolvable symbolic ref
        };
        // git shortens `refs/remotes/<remote>/HEAD` to just `<remote>`;
        // git2's `shorthand` keeps the trailing `/HEAD`, so special-case it.
        let short = name
            .strip_prefix("refs/remotes/")
            .and_then(|rest| rest.strip_suffix("/HEAD"))
            .unwrap_or_else(|| reference.shorthand().unwrap_or(name));
        let subject = if want_subject {
            ref_subject(&repo, oid)
        } else {
            String::new()
        };
        let line = expand_ref_format(format, name, short, &oid.to_string(), &subject);
        rows.push((name.to_string(), line));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (_, line) in rows {
        let _ = writeln!(out, "{line}");
    }
    Ok(Output::ok_str(out))
}

/// Expand the supported `for-each-ref` `--format` placeholders for one ref.
///
/// `%(refname:short)` is substituted before `%(refname)` so the longer token
/// wins; `%00`/`%09` map to NUL/tab.
fn expand_ref_format(format: &str, refname: &str, short: &str, oid: &str, subject: &str) -> String {
    format
        .replace("%(refname:short)", short)
        .replace("%(refname)", refname)
        .replace("%(objectname)", oid)
        .replace("%(contents:subject)", subject)
        .replace("%00", "\0")
        .replace("%09", "\t")
}

/// The subject line (first line of the message) of the commit or annotated tag
/// that `oid` resolves to, or an empty string when it has none.
fn ref_subject(repo: &git2::Repository, oid: git2::Oid) -> String {
    let Ok(object) = repo.find_object(oid, None) else {
        return String::new();
    };
    if let Some(tag) = object.as_tag() {
        return first_line(tag.message().ok().flatten());
    }
    match object.peel_to_commit() {
        Ok(commit) => first_line(commit.message().ok()),
        Err(_) => String::new(),
    }
}

/// The first line of `message` (git's "subject"), trimmed; empty when absent.
fn first_line(message: Option<&str>) -> String {
    message
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// `git cat-file -p <spec>` / `git show <spec>` for blobs and tag/commit objects.
fn cat_file_p(dir: &Path, spec: &str) -> Result<Output> {
    match resolve_blob_bytes(&open(dir)?, spec)? {
        Some(bytes) => Ok(Output::ok(bytes)),
        None => Ok(Output::fail(format!("{spec} does not exist"))),
    }
}

/// Read the object bytes named by `spec`, supporting the `:path` (stage-0
/// index) and `<treeish>:path` revspecs git uses for staged/tree blobs in
/// addition to ordinary revisions.
fn resolve_blob_bytes(repo: &Repository, spec: &str) -> Result<Option<Vec<u8>>> {
    // ":path" or ":0:path" names a stage-0 index entry, which git2's revparse
    // does not resolve.
    if let Some(rest) = spec.strip_prefix(':') {
        if !rest.starts_with(':') {
            let path = rest.strip_prefix("0:").unwrap_or(rest);
            let index = repo.index().context("opening index")?;
            return match index.get_path(Path::new(path), 0) {
                Some(entry) => {
                    let odb = repo.odb().context("opening object database")?;
                    let raw = odb.read(entry.id).context("reading staged object")?;
                    Ok(Some(raw.data().to_vec()))
                }
                None => Ok(None),
            };
        }
    }
    match repo.revparse_single(spec) {
        Ok(object) => {
            let odb = repo.odb().context("opening object database")?;
            let raw = odb.read(object.id()).context("reading object")?;
            Ok(Some(raw.data().to_vec()))
        }
        Err(_) => Ok(None),
    }
}

/// `git config <key>` (read from the repository configuration).
fn config_get(dir: &Path, key: &str) -> Result<Output> {
    let repo = open(dir)?;
    let config = repo.config().context("opening git config")?;
    match config.get_string(key) {
        Ok(value) => Ok(Output::ok_str(value)),
        Err(_) => Ok(Output::fail(format!("config key {key} is unset"))),
    }
}

/// `git config <key> <value>` (write to the repository configuration).
fn config_set(dir: &Path, key: &str, value: &str) -> Result<Output> {
    let repo = open(dir)?;
    let mut config = repo.config().context("opening git config")?;
    config
        .set_str(key, value)
        .with_context(|| format!("setting config {key}"))?;
    Ok(Output::ok_str(""))
}

/// `git add [-A] [--] [<pathspec>...]` (also `git add .`).
fn add(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let mut index = repo.index().context("opening index")?;
    // Strip flags/separators, leaving the pathspecs.
    let mut specs: Vec<&str> = Vec::new();
    for arg in rest {
        match *arg {
            "-A" | "--all" | "--" => {}
            other => specs.push(other),
        }
    }
    if specs.is_empty() || specs == ["."] {
        specs = vec!["*"];
    }
    // add_all is the equivalent of `git add -A`: it stages additions,
    // modifications, and deletions for the matched paths, honoring .gitignore.
    index
        .add_all(specs.iter(), git2::IndexAddOption::DEFAULT, None)
        .context("staging changes")?;
    index.write().context("writing index")?;
    Ok(Output::ok_str(""))
}

/// Resolve the commit identity, falling back to a default when neither the
/// configuration nor the environment provides one (git's lenient behavior,
/// which the registry relies on for unsigned bootstrap commits).
fn commit_identity(repo: &Repository) -> Result<git2::Signature<'static>> {
    if let Ok(sig) = repo.signature() {
        return Ok(sig);
    }
    let name = std::env::var("GIT_AUTHOR_NAME")
        .or_else(|_| std::env::var("GIT_COMMITTER_NAME"))
        .unwrap_or_else(|_| "AOS Registry".to_string());
    let email = std::env::var("GIT_AUTHOR_EMAIL")
        .or_else(|_| std::env::var("GIT_COMMITTER_EMAIL"))
        .unwrap_or_else(|_| "registry@localhost".to_string());
    git2::Signature::now(&name, &email).context("building commit identity")
}

/// `git commit -m <message>` (unsigned). Signed commits are created directly
/// in `registry_ops` so the SSH signature can be attached.
fn commit_unsigned(dir: &Path, message: &str) -> Result<Output> {
    let repo = open(dir)?;
    let mut index = repo.index().context("opening index")?;
    let tree_oid = index.write_tree().context("writing tree")?;
    let tree = repo.find_tree(tree_oid).context("reading tree")?;
    let sig = commit_identity(&repo)?;
    let parents = match repo.head() {
        Ok(head) => vec![head.peel_to_commit().context("reading HEAD commit")?],
        Err(_) => Vec::new(),
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    let oid = repo
        .commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .context("creating commit")?;
    Ok(Output::ok_str(oid.to_string()))
}

/// `git tag --list`.
fn tag_list(dir: &Path) -> Result<Output> {
    let repo = open(dir)?;
    let names = repo.tag_names(None).context("listing tags")?;
    let mut out = String::new();
    for name in names.iter().flatten().flatten() {
        let _ = writeln!(out, "{name}");
    }
    Ok(Output::ok_str(out))
}

/// `git tag -d <name>`.
fn tag_delete(dir: &Path, name: &str) -> Result<Output> {
    let repo = open(dir)?;
    match repo.tag_delete(name) {
        Ok(()) => Ok(Output::ok_str("")),
        Err(e) => Ok(Output::fail(e.message().to_string())),
    }
}

/// `git remote`.
fn remotes(dir: &Path) -> Result<Output> {
    let repo = open(dir)?;
    let remotes = repo.remotes().context("listing remotes")?;
    let mut out = String::new();
    for name in remotes.iter().flatten().flatten() {
        let _ = writeln!(out, "{name}");
    }
    Ok(Output::ok_str(out))
}

/// `git remote get-url <name>`.
fn remote_url(dir: &Path, name: &str) -> Result<Output> {
    let repo = open(dir)?;
    match repo.find_remote(name) {
        Ok(remote) => Ok(Output::ok_str(remote.url().unwrap_or("").to_string())),
        Err(e) => Ok(Output::fail(e.message().to_string())),
    }
}

/// `git update-ref <name> <oid>`.
fn update_ref(dir: &Path, name: &str, oid: &str) -> Result<Output> {
    let repo = open(dir)?;
    let target = match repo.revparse_single(oid) {
        Ok(object) => object.id(),
        Err(e) => return Ok(Output::fail(e.message().to_string())),
    };
    repo.reference(name, target, true, "apr update-ref")
        .with_context(|| format!("updating ref {name}"))?;
    Ok(Output::ok_str(""))
}

/// Map a libgit2 [`Status`] to a porcelain two-letter `XY` code.
fn porcelain_code(status: Status) -> [u8; 2] {
    if status.contains(Status::WT_NEW) && !status.intersects(Status::INDEX_NEW) {
        return [b'?', b'?'];
    }
    let x = if status.contains(Status::INDEX_NEW) {
        b'A'
    } else if status.contains(Status::INDEX_MODIFIED) {
        b'M'
    } else if status.contains(Status::INDEX_DELETED) {
        b'D'
    } else if status.contains(Status::INDEX_RENAMED) {
        b'R'
    } else if status.contains(Status::INDEX_TYPECHANGE) {
        b'T'
    } else {
        b' '
    };
    let y = if status.contains(Status::WT_MODIFIED) {
        b'M'
    } else if status.contains(Status::WT_DELETED) {
        b'D'
    } else if status.contains(Status::WT_RENAMED) {
        b'R'
    } else if status.contains(Status::WT_TYPECHANGE) {
        b'T'
    } else {
        b' '
    };
    [x, y]
}

/// `git status --porcelain` / `git status --short [--untracked-files=all]`.
fn status(dir: &Path, _rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo.statuses(Some(&mut opts)).context("computing status")?;
    let mut out = String::new();
    for entry in statuses.iter() {
        let code = porcelain_code(entry.status());
        let path = entry.path().unwrap_or("");
        let _ = writeln!(out, "{}{} {path}", code[0] as char, code[1] as char);
    }
    Ok(Output::ok_str(out))
}

/// `git ls-files [--others --exclude-standard] [-- <pathspec>]`.
fn ls_files(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let others = rest.contains(&"--others");
    let pathspec = rest
        .iter()
        .position(|a| *a == "--")
        .and_then(|i| rest.get(i + 1))
        .copied();

    let mut out = String::new();
    if others {
        // Untracked, ignored-excluded files.
        let mut opts = git2::StatusOptions::new();
        opts.include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(false);
        let statuses = repo
            .statuses(Some(&mut opts))
            .context("listing untracked files")?;
        for entry in statuses.iter() {
            if entry.status().contains(Status::WT_NEW) {
                if let Ok(path) = entry.path() {
                    let _ = writeln!(out, "{path}");
                }
            }
        }
    } else {
        let index = repo.index().context("opening index")?;
        for entry in index.iter() {
            let path = String::from_utf8_lossy(&entry.path);
            if let Some(spec) = pathspec {
                if !path.starts_with(spec) {
                    continue;
                }
            }
            let _ = writeln!(out, "{path}");
        }
    }
    Ok(Output::ok_str(out))
}

/// Resolve a tree for `spec` (HEAD, a ref, or the index when `spec` is None).
fn resolve_tree<'a>(repo: &'a Repository, spec: Option<&str>) -> Result<Option<git2::Tree<'a>>> {
    match spec {
        Some(spec) => {
            let object = repo
                .revparse_single(spec)
                .with_context(|| format!("resolving {spec}"))?;
            Ok(Some(
                object
                    .peel_to_tree()
                    .with_context(|| format!("{spec} has no tree"))?,
            ))
        }
        None => Ok(None),
    }
}

/// `git diff [--cached] [--name-only|--name-status|--stat] [base [head]]`.
fn diff(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let cached = rest.contains(&"--cached");
    let name_only = rest.contains(&"--name-only");
    let name_status = rest.contains(&"--name-status");
    let stat = rest.contains(&"--stat");
    let positionals: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| !a.starts_with("--"))
        .collect();

    let mut diff_opts = git2::DiffOptions::new();
    let diff = if cached {
        // Staged changes vs HEAD.
        let head_tree = repo.head().ok().and_then(|h| h.peel_to_tree().ok());
        repo.diff_tree_to_index(head_tree.as_ref(), None, Some(&mut diff_opts))
            .context("diffing index against HEAD")?
    } else if positionals.len() == 2 {
        let base = resolve_tree(&repo, Some(positionals[0]))?;
        let head = resolve_tree(&repo, Some(positionals[1]))?;
        repo.diff_tree_to_tree(base.as_ref(), head.as_ref(), Some(&mut diff_opts))
            .context("diffing two trees")?
    } else if positionals.len() == 1 {
        let base = resolve_tree(&repo, Some(positionals[0]))?;
        repo.diff_tree_to_workdir_with_index(base.as_ref(), Some(&mut diff_opts))
            .context("diffing tree against worktree")?
    } else {
        repo.diff_index_to_workdir(None, Some(&mut diff_opts))
            .context("diffing worktree")?
    };

    if stat {
        let stats = diff.stats().context("computing diff stats")?;
        let buf = stats
            .to_buf(git2::DiffStatsFormat::FULL, 80)
            .context("formatting diff stats")?;
        return Ok(Output::ok(buf.to_vec()));
    }

    let mut out = String::new();
    if name_status {
        diff.foreach(
            &mut |delta, _| {
                let ch = match delta.status() {
                    git2::Delta::Added => 'A',
                    git2::Delta::Deleted => 'D',
                    git2::Delta::Modified => 'M',
                    git2::Delta::Renamed => 'R',
                    git2::Delta::Copied => 'C',
                    git2::Delta::Typechange => 'T',
                    _ => 'M',
                };
                if let Some(path) = delta.new_file().path().and_then(|p| p.to_str()) {
                    let _ = writeln!(out, "{ch}\t{path}");
                }
                true
            },
            None,
            None,
            None,
        )
        .context("walking diff")?;
    } else if name_only {
        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path().and_then(|p| p.to_str()) {
                    let _ = writeln!(out, "{path}");
                }
                true
            },
            None,
            None,
            None,
        )
        .context("walking diff")?;
    } else {
        // Full patch text.
        let mut patch = Vec::new();
        diff.print(git2::DiffFormat::Patch, |_, _, line| {
            match line.origin() {
                '+' | '-' | ' ' => patch.push(line.origin() as u8),
                _ => {}
            }
            patch.extend_from_slice(line.content());
            true
        })
        .context("printing diff")?;
        return Ok(Output::ok(patch));
    }
    Ok(Output::ok_str(out))
}

/// `git log [--oneline] [-N] [--pretty=format:<fmt>|--format=<fmt>] [<rev>]
/// [-- <path>]`.
///
/// Supports the `--oneline` shorthand and the `%H %h %s %B %ct %x1f %x1e %n %%`
/// pretty placeholders that `apr` uses; output is the per-commit formatted
/// records joined verbatim. When one or more `<rev>` arguments are given the
/// walk is seeded from them instead of `HEAD`, and `--format=` is accepted as
/// an alias for `--pretty=format:`.
fn log(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let limit = rest
        .iter()
        .find_map(|a| a.strip_prefix('-').and_then(|n| n.parse::<usize>().ok()));
    let path = rest
        .iter()
        .position(|a| *a == "--")
        .and_then(|i| rest.get(i + 1))
        .copied();
    // Revisions are the non-flag positionals before any `--` path separator.
    let revs: Vec<&str> = match rest.iter().position(|a| *a == "--") {
        Some(separator) => &rest[..separator],
        None => rest,
    }
    .iter()
    .copied()
    .filter(|a| !a.starts_with('-'))
    .collect();
    let format = rest
        .iter()
        .find_map(|a| a.strip_prefix("--pretty=format:"))
        .or_else(|| rest.iter().find_map(|a| a.strip_prefix("--format=")))
        .map(ToString::to_string)
        // `--oneline` is shorthand for the abbreviated hash plus the subject.
        .unwrap_or_else(|| "%h %s".to_string());

    let mut walk = repo.revwalk().context("creating revwalk")?;
    if revs.is_empty() {
        if walk.push_head().is_err() {
            return Ok(Output::ok_str(""));
        }
    } else {
        for rev in revs {
            let object = match repo.revparse_single(rev) {
                Ok(object) => object,
                Err(e) => return Ok(Output::fail(e.message().to_string())),
            };
            let commit = match object.peel_to_commit() {
                Ok(commit) => commit,
                Err(e) => return Ok(Output::fail(e.message().to_string())),
            };
            walk.push(commit.id()).context("seeding revwalk")?;
        }
    }
    let mut out = String::new();
    let mut shown = 0;
    for oid in walk {
        if limit.is_some_and(|l| shown >= l) {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid).context("reading commit")?;
        if let Some(path) = path {
            if !commit_touches_path(&repo, &commit, path)? {
                continue;
            }
        }
        out.push_str(&format_commit(&commit, &format));
        out.push('\n');
        shown += 1;
    }
    Ok(Output::ok_str(out))
}

/// Expand a git `--pretty=format` template for `commit`.
fn format_commit(commit: &git2::Commit<'_>, format: &str) -> String {
    let short = commit
        .as_object()
        .short_id()
        .ok()
        .and_then(|buf| buf.as_str().ok().map(ToString::to_string))
        .unwrap_or_else(|| commit.id().to_string());
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('B') => out.push_str(commit.message().ok().unwrap_or("")),
            Some('H') => out.push_str(&commit.id().to_string()),
            Some('h') => out.push_str(&short),
            Some('s') => out.push_str(commit.summary().ok().flatten().unwrap_or("")),
            Some('c') if chars.peek() == Some(&'t') => {
                chars.next();
                let _ = write!(out, "{}", commit.time().seconds());
            }
            Some('n') => out.push('\n'),
            Some('%') => out.push('%'),
            Some('x') => {
                // %xNN — a literal byte in two hex digits.
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(hi), Some(lo)) = (hi, lo)
                    && let Ok(byte) = u8::from_str_radix(&format!("{hi}{lo}"), 16)
                {
                    out.push(byte as char);
                }
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Whether `commit` changed `path` relative to its first parent (or added it
/// in a root commit).
fn commit_touches_path(repo: &Repository, commit: &git2::Commit, path: &str) -> Result<bool> {
    let tree = commit.tree().context("reading commit tree")?;
    let parent_tree = match commit.parent(0) {
        Ok(parent) => Some(parent.tree().context("reading parent tree")?),
        Err(_) => None,
    };
    let mut opts = git2::DiffOptions::new();
    opts.pathspec(path);
    let diff = repo
        .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut opts))
        .context("diffing commit against parent")?;
    Ok(diff.deltas().len() > 0)
}

/// `git branch [-a] [--show-current] [-d] [--] [<name>]`.
fn branch(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    if rest.contains(&"--show-current") {
        return Ok(match repo.head() {
            Ok(head) if head.is_branch() => {
                Output::ok_str(head.shorthand().unwrap_or("").to_string())
            }
            _ => Output::ok_str(""),
        });
    }
    let name = rest
        .iter()
        .copied()
        .find(|a| !a.starts_with('-') && *a != "--");
    let force_delete = rest.contains(&"-D");
    if rest.contains(&"-d") || force_delete {
        let Some(name) = name else {
            bail!("git branch -d requires a name");
        };
        let mut b = repo
            .find_branch(name, git2::BranchType::Local)
            .with_context(|| format!("finding branch {name}"))?;
        // `-d` is the merge-safe delete: refuse a branch whose tip is not
        // reachable from HEAD (git2's `Branch::delete` is unconditional, i.e.
        // `-D` semantics, so the check is ours to enforce). `-D` force-deletes.
        if !force_delete {
            let branch_oid = b
                .get()
                .peel_to_commit()
                .with_context(|| format!("reading branch {name} tip"))?
                .id();
            let head_oid = repo
                .head()
                .context("resolving HEAD")?
                .peel_to_commit()
                .context("HEAD commit")?
                .id();
            let merged = branch_oid == head_oid
                || repo
                    .graph_descendant_of(head_oid, branch_oid)
                    .unwrap_or(false);
            if !merged {
                return Ok(Output::fail(format!(
                    "the branch '{name}' is not fully merged"
                )));
            }
        }
        b.delete()
            .with_context(|| format!("deleting branch {name}"))?;
        return Ok(Output::ok_str(""));
    }
    if let Some(name) = name {
        // Create a branch at HEAD.
        let head = repo
            .head()
            .context("resolving HEAD")?
            .peel_to_commit()
            .context("HEAD commit")?;
        repo.branch(name, &head, false)
            .with_context(|| format!("creating branch {name}"))?;
        return Ok(Output::ok_str(""));
    }
    // List branches.
    let all = rest.contains(&"-a");
    let mut out = String::new();
    let filter = if all {
        None
    } else {
        Some(git2::BranchType::Local)
    };
    for item in repo.branches(filter).context("listing branches")? {
        let (b, _) = item?;
        if let Some(name) = b.name().ok().flatten() {
            let marker = if b.is_head() { "* " } else { "  " };
            let _ = writeln!(out, "{marker}{name}");
        }
    }
    Ok(Output::ok_str(out))
}

/// `git switch -- <name>`: check out an existing branch.
fn switch(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let Some(name) = rest
        .iter()
        .copied()
        .find(|a| !a.starts_with('-') && *a != "--")
    else {
        bail!("git switch requires a branch name");
    };
    let refname = format!("refs/heads/{name}");
    let object = repo
        .revparse_single(&refname)
        .with_context(|| format!("resolving branch {name}"))?;
    repo.checkout_tree(&object, None)
        .with_context(|| format!("checking out {name}"))?;
    repo.set_head(&refname)
        .with_context(|| format!("switching HEAD to {name}"))?;
    Ok(Output::ok_str(""))
}

/// `git merge [--no-ff] [--squash] -- <branch>` (fast-forward or a simple
/// in-memory merge with a merge commit).
fn merge(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let squash = rest.contains(&"--squash");
    let no_ff = rest.contains(&"--no-ff");
    let Some(name) = rest
        .iter()
        .copied()
        .find(|a| !a.starts_with('-') && *a != "--")
    else {
        bail!("git merge requires a branch name");
    };

    let their_commit = repo
        .revparse_single(name)
        .with_context(|| format!("resolving {name}"))?
        .peel_to_commit()
        .context("merge source is not a commit")?;
    let their_annotated = repo
        .find_annotated_commit(their_commit.id())
        .context("annotating merge source")?;
    let (analysis, _) = repo
        .merge_analysis(&[&their_annotated])
        .context("merge analysis")?;

    let head = repo.head().context("resolving HEAD")?;
    let head_commit = head.peel_to_commit().context("reading HEAD commit")?;

    if analysis.is_up_to_date() {
        return Ok(Output::ok_str("Already up to date.\n"));
    }
    if analysis.is_fast_forward() && !no_ff && !squash {
        let refname = head.name().context("HEAD has no name")?.to_string();
        repo.reference(&refname, their_commit.id(), true, "apr merge ff")
            .context("fast-forwarding")?;
        let object = repo
            .find_object(their_commit.id(), None)
            .context("merge target")?;
        // Force the working tree/index to the fast-forward target. git2's
        // default SAFE checkout diffs against HEAD, which we just advanced to
        // `their_commit`; every fast-forwarded file would then look like a
        // local modification and be skipped, leaving the working tree stale
        // (so `apr show`/`apr packages` would read pre-merge data). A real
        // `git` fast-forward resets the working tree to the target, so force.
        let mut checkout = git2::build::CheckoutBuilder::new();
        checkout.force();
        repo.checkout_tree(&object, Some(&mut checkout))
            .context("checking out merge result")?;
        return Ok(Output::ok_str("Fast-forward\n"));
    }

    // Three-way merge into the index/worktree.
    let mut their_tree_index = repo
        .merge_commits(&head_commit, &their_commit, None)
        .context("merging commits")?;
    if their_tree_index.has_conflicts() {
        return Ok(Output::fail("merge has conflicts"));
    }
    let tree_oid = their_tree_index
        .write_tree_to(&repo)
        .context("writing merged tree")?;
    let tree = repo.find_tree(tree_oid).context("reading merged tree")?;
    let merged = repo
        .find_object(tree_oid, None)
        .context("merge tree object")?;
    repo.checkout_tree(&merged, None)
        .context("checking out merged tree")?;

    if squash {
        // Stage the merged tree but leave the commit to the caller.
        let mut index = repo.index().context("opening index")?;
        index
            .read_tree(&tree)
            .context("reading merged tree into index")?;
        index.write().context("writing index")?;
        return Ok(Output::ok_str("Squash commit -- not updating HEAD\n"));
    }

    let sig = commit_identity(&repo)?;
    let message = format!("Merge branch '{name}'");
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        &message,
        &tree,
        &[&head_commit, &their_commit],
    )
    .context("creating merge commit")?;
    Ok(Output::ok_str("Merge made by the 'recursive' strategy.\n"))
}

/// `git push [<remote>] [<branch>...]` (defaults to `origin` and the current
/// branch). Pushes `refs/heads/<branch>` to the same ref on the remote.
fn push(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let positionals: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let remote_name = positionals.first().copied().unwrap_or("origin");
    let branches: Vec<&str> = positionals.iter().skip(1).copied().collect();

    let refspecs: Vec<String> = if branches.is_empty() {
        let head = repo.head().context("resolving HEAD")?;
        let name = head
            .shorthand()
            .context("HEAD is not a branch")?
            .to_string();
        vec![format!("refs/heads/{name}:refs/heads/{name}")]
    } else {
        branches
            .iter()
            .map(|b| format!("refs/heads/{b}:refs/heads/{b}"))
            .collect()
    };

    let mut remote = repo
        .find_remote(remote_name)
        .with_context(|| format!("finding remote {remote_name}"))?;
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(crate::registry::repo::credentials);
    let mut opts = git2::PushOptions::new();
    opts.remote_callbacks(callbacks);
    let refs: Vec<&str> = refspecs.iter().map(String::as_str).collect();
    match remote.push(&refs, Some(&mut opts)) {
        Ok(()) => Ok(Output::ok_str("")),
        Err(e) => Ok(Output::fail(e.message().to_string())),
    }
}

/// `git read-tree -u --reset <treeish>` via libgit2.
///
/// Resets both the index and the working tree to `<treeish>`, discarding local
/// modifications (the `--reset` + `-u` semantics `apr change merge` uses to
/// stage a draft's tree before re-committing it).
///
/// # Errors
///
/// Returns an error if the repository cannot be opened, the revision does not
/// resolve to a tree, or the checkout/index update fails.
fn read_tree_reset(dir: &Path, treeish: &str) -> Result<Output> {
    let repo = open(dir)?;
    let tree = repo
        .revparse_single(treeish)
        .with_context(|| format!("resolving {treeish}"))?
        .peel_to_tree()
        .with_context(|| format!("{treeish} is not a tree"))?;
    let mut checkout = git2::build::CheckoutBuilder::new();
    checkout.force().remove_untracked(true);
    repo.checkout_tree(tree.as_object(), Some(&mut checkout))
        .context("resetting working tree to tree")?;
    let mut index = repo.index().context("opening index")?;
    index.read_tree(&tree).context("reading tree into index")?;
    index.write().context("writing index")?;
    Ok(Output::ok_str(""))
}

/// `git merge-base --is-ancestor <ancestor> <descendant>` via libgit2.
///
/// Succeeds (exit 0, [`Output::success`] true) when `<ancestor>` is reachable
/// from `<descendant>` — i.e. is an ancestor of it, or the two are the same
/// commit — and fails (non-zero) otherwise, matching git's exit-code contract.
///
/// # Errors
///
/// Returns an error if the repository cannot be opened or either revision does
/// not resolve to a commit.
fn merge_base_is_ancestor(dir: &Path, ancestor: &str, descendant: &str) -> Result<Output> {
    let repo = open(dir)?;
    let resolve = |spec: &str| -> Result<git2::Oid> {
        Ok(repo
            .revparse_single(spec)
            .with_context(|| format!("resolving {spec}"))?
            .peel_to_commit()
            .with_context(|| format!("{spec} is not a commit"))?
            .id())
    };
    let ancestor_oid = resolve(ancestor)?;
    let descendant_oid = resolve(descendant)?;
    let is_ancestor = ancestor_oid == descendant_oid
        || repo
            .graph_descendant_of(descendant_oid, ancestor_oid)
            .unwrap_or(false);
    Ok(if is_ancestor {
        Output::ok_str("")
    } else {
        Output::fail(String::new())
    })
}

/// `git fetch <remote> [<refspec>...] [--force]` via libgit2.
///
/// Fetches the named refspecs (or the remote's configured refspecs when none
/// are given) into their local destination refs, without touching the working
/// tree. The first non-flag argument is the remote (defaulting to `origin`);
/// the rest are refspecs. `--force` and other flags are accepted but ignored —
/// a leading `+` on a refspec already forces the update — and a git-level
/// failure (e.g. an unreachable remote) is reported through [`Output`].
fn fetch(dir: &Path, args: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let mut remote_name = "origin";
    let mut refspecs: Vec<&str> = Vec::new();
    let mut saw_remote = false;
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        if saw_remote {
            refspecs.push(arg);
        } else {
            remote_name = arg;
            saw_remote = true;
        }
    }
    let mut remote = repo
        .find_remote(remote_name)
        .with_context(|| format!("finding remote {remote_name}"))?;
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(crate::registry::repo::credentials);
    let mut fetch_opts = git2::FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    match remote.fetch(&refspecs, Some(&mut fetch_opts), None) {
        Ok(()) => Ok(Output::ok_str("")),
        Err(e) => Ok(Output::fail(e.message().to_string())),
    }
}

/// `git pull [--rebase]` from `origin` into the current branch.
///
/// Fetches the remote's configured refspecs and fast-forwards when possible.
/// For a divergent history, `--rebase` replays the local commits on top of the
/// fetched commit (keeping the branch linear); without it a merge commit is
/// created.
fn pull(dir: &Path, rest: &[&str]) -> Result<Output> {
    let repo = open(dir)?;
    let rebase = rest.iter().any(|arg| *arg == "--rebase");
    let mut remote = repo
        .find_remote("origin")
        .context("finding remote origin")?;
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(crate::registry::repo::credentials);
    let mut fetch_opts = git2::FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    let empty: [&str; 0] = [];
    if let Err(e) = remote.fetch(&empty, Some(&mut fetch_opts), None) {
        return Ok(Output::fail(e.message().to_string()));
    }

    let fetch_head = repo
        .find_reference("FETCH_HEAD")
        .context("reading FETCH_HEAD")?;
    let fetched = repo
        .reference_to_annotated_commit(&fetch_head)
        .context("annotating FETCH_HEAD")?;
    let (analysis, _) = repo.merge_analysis(&[&fetched]).context("merge analysis")?;

    if analysis.is_up_to_date() {
        return Ok(Output::ok_str("Already up to date.\n"));
    }
    if analysis.is_fast_forward() {
        let mut head = repo.head().context("resolving HEAD")?;
        let refname = head.name().context("HEAD has no name")?.to_string();
        head.set_target(fetched.id(), "apr pull ff")
            .with_context(|| format!("fast-forwarding {refname}"))?;
        repo.set_head(&refname).context("updating HEAD")?;
        repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .context("checking out pulled tree")?;
        return Ok(Output::ok_str("Fast-forward\n"));
    }

    let sig = commit_identity(&repo)?;

    // Divergent history with `--rebase`: replay the local commits onto the
    // fetched commit so the branch stays linear (no merge commit).
    if rebase {
        let head_ann = {
            let head = repo.head().context("resolving HEAD")?;
            repo.reference_to_annotated_commit(&head)
                .context("annotating HEAD")?
        };
        let mut rb = repo
            .rebase(Some(&head_ann), Some(&fetched), None, None)
            .context("starting rebase")?;
        while let Some(op) = rb.next() {
            op.context("rebase operation")?;
            if repo.index().context("rebase index")?.has_conflicts() {
                rb.abort().ok();
                return Ok(Output::fail("pull --rebase has conflicts"));
            }
            rb.commit(None, &sig, None)
                .context("committing rebased change")?;
        }
        rb.finish(None).context("finishing rebase")?;
        return Ok(Output::ok_str("Rebased\n"));
    }

    // Non-fast-forward merge: create a merge commit and force the working tree
    // to the merged result. git2's default SAFE checkout diffs against HEAD and
    // would skip files that differ from it, leaving the worktree stale (the
    // same hazard as the fast-forward path above).
    let head_commit = repo
        .head()
        .context("HEAD")?
        .peel_to_commit()
        .context("HEAD commit")?;
    let their_commit = repo.find_commit(fetched.id()).context("fetched commit")?;
    let mut merged = repo
        .merge_commits(&head_commit, &their_commit, None)
        .context("merging")?;
    if merged.has_conflicts() {
        return Ok(Output::fail("pull merge has conflicts"));
    }
    let tree_oid = merged.write_tree_to(&repo).context("writing merged tree")?;
    let tree = repo.find_tree(tree_oid).context("merged tree")?;
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "Merge remote-tracking branch 'origin'",
        &tree,
        &[&head_commit, &their_commit],
    )
    .context("merge commit")?;
    let merged_obj = repo.find_object(tree_oid, None).context("merged object")?;
    let mut checkout = git2::build::CheckoutBuilder::new();
    checkout.force();
    repo.checkout_tree(&merged_obj, Some(&mut checkout))
        .context("checking out merge")?;
    Ok(Output::ok_str("Merge made by the 'recursive' strategy.\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A repo with a `stable` branch plus an `origin/stable` remote-tracking
    /// ref and a symbolic `origin/HEAD`, returning the dir and the commit hex.
    fn repo_with_remote() -> (TempDir, String) {
        let tmp = TempDir::new().expect("tempdir");
        let repo = git2::Repository::init(tmp.path()).expect("init");
        let sig = git2::Signature::now("Test", "test@test").expect("signature");
        let tree_oid = repo
            .treebuilder(None)
            .expect("treebuilder")
            .write()
            .expect("write tree");
        let tree = repo.find_tree(tree_oid).expect("tree");
        let commit = repo
            .commit(Some("refs/heads/stable"), &sig, &sig, "init", &tree, &[])
            .expect("commit");
        repo.set_head("refs/heads/stable").expect("set head");
        repo.reference("refs/remotes/origin/stable", commit, true, "")
            .expect("remote-tracking ref");
        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/stable",
            true,
            "",
        )
        .expect("symbolic remote HEAD");
        (tmp, commit.to_string())
    }

    /// `for-each-ref` reproduces git's output: one expanded line per ref under
    /// the requested prefixes, sorted by full refname, with `%00` as NUL and
    /// `origin/HEAD` shortened to `origin` — the path `apr --json` publish
    /// drives through `git_branch_entries` when a remote is configured
    /// (regression for the libgit2 port, which omitted the subcommand and
    /// failed publish with `unsupported git invocation`).
    #[test]
    fn for_each_ref_matches_git_format() {
        let (tmp, oid) = repo_with_remote();
        let out = dispatch(
            tmp.path(),
            &[
                "for-each-ref",
                "--format=%(refname)%00%(refname:short)%00%(objectname)%00",
                "refs/heads",
                "refs/remotes",
            ],
        )
        .expect("dispatch");
        assert!(out.success);
        let text = String::from_utf8(out.stdout).expect("utf8 output");
        let expected = format!(
            "refs/heads/stable\0stable\0{oid}\0\n\
             refs/remotes/origin/HEAD\0origin\0{oid}\0\n\
             refs/remotes/origin/stable\0origin/stable\0{oid}\0\n"
        );
        assert_eq!(text, expected);
    }

    /// A prefix that matches nothing yields empty output and still succeeds.
    #[test]
    fn for_each_ref_empty_when_no_match() {
        let (tmp, _) = repo_with_remote();
        let out = dispatch(
            tmp.path(),
            &[
                "for-each-ref",
                "--format=%(refname)%00%(refname:short)%00%(objectname)%00",
                "refs/tags",
            ],
        )
        .expect("dispatch");
        assert!(out.success);
        assert!(out.stdout.is_empty());
    }

    /// The `--format` string is expanded generally: `%(objectname)`, the `%09`
    /// tab escape, `%(refname)`, and `%(contents:subject)` each interpolate per
    /// matching ref (the shape `apr change list` uses).
    #[test]
    fn for_each_ref_expands_general_format() {
        let (tmp, oid) = repo_with_remote();
        let out = dispatch(
            tmp.path(),
            &[
                "for-each-ref",
                "--format=%(objectname)%09%(refname)",
                "refs/heads",
            ],
        )
        .expect("dispatch");
        assert!(out.success);
        let text = String::from_utf8(out.stdout).expect("utf8 output");
        assert_eq!(text, format!("{oid}\trefs/heads/stable\n"));
    }

    /// `git log -1 --format=%B <rev>` returns the *named* revision's full
    /// message body, not HEAD's — the path `apr change` reads a draft's body
    /// through. Regression for the libgit2 port, which only understood
    /// `--pretty=format:` and always walked from HEAD, so an explicit rev plus
    /// `--format=%B` silently degraded to `%h %s` of the tip commit.
    #[test]
    fn log_format_body_reads_named_revision() {
        let tmp = TempDir::new().expect("tempdir");
        let repo = git2::Repository::init(tmp.path()).expect("init");
        let sig = git2::Signature::now("Test", "test@test").expect("signature");
        let tree = repo
            .find_tree(
                repo.treebuilder(None)
                    .expect("treebuilder")
                    .write()
                    .expect("write tree"),
            )
            .expect("tree");
        // The older commit carries a multi-line body and is an ancestor of HEAD.
        let first = repo
            .commit(
                Some("refs/heads/main"),
                &sig,
                &sig,
                "first subject\n\nfirst body line\n",
                &tree,
                &[],
            )
            .expect("first commit");
        let first_commit = repo.find_commit(first).expect("find first");
        // HEAD advances past it with a different message.
        repo.commit(
            Some("refs/heads/main"),
            &sig,
            &sig,
            "second subject\n\nsecond body line\n",
            &tree,
            &[&first_commit],
        )
        .expect("second commit");
        repo.set_head("refs/heads/main").expect("set head");

        let out = dispatch(
            tmp.path(),
            &["log", "-1", "--format=%B", &first.to_string()],
        )
        .expect("dispatch");
        assert!(out.success);
        let text = String::from_utf8(out.stdout).expect("utf8 output");
        // The full raw body of the named commit (which `%s` would truncate to
        // its subject), plus `log`'s trailing record-separator newline.
        let body = first_commit.message().expect("message");
        assert_eq!(text, format!("{body}\n"));
        assert!(
            !text.contains("second"),
            "log must read the named rev, not HEAD: {text:?}"
        );
    }
}
