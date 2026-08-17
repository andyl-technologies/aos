//! Tree-walk evaluator tests: locked-`fetchGit` reuse records.
//!
//! Covers the durable input-to-result records that let a rev-pinned
//! `builtins.fetchGit` answer from an already-materialized store path without
//! re-cloning (`fetch_git_store.rs`). The strongest observation that no git
//! work happens on reuse is deleting the source repository between
//! evaluations: the second evaluation can only succeed through the record.

use super::*;

/// Evaluator options with an isolated store and reuse-record directory.
fn reuse_options(store_dir: &Path, cache_dir: &Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_env_var(
        b"AOS_NIX_FETCH_GIT_CACHE".to_vec(),
        cache_dir.as_os_str().as_bytes().to_vec(),
    );
    options
}

/// The fetchGit metadata projection compared byte-for-byte across runs.
fn fetch_git_metadata_source(url: &str, rev: &str) -> String {
    format!(
        r#"
            let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
            in {{
              pathValue = x.outPath;
              rev = x.rev;
              shortRev = x.shortRev;
              revCount = x.revCount;
              lastModified = x.lastModified;
              lastModifiedDate = x.lastModifiedDate;
              narHash = x.narHash;
              submodules = x.submodules;
            }}
            "#,
        url = nix_string_literal(url),
    )
}

#[test]
fn locked_fetch_git_reuses_record_without_the_source_repo() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-reuse");
    let store_dir = unique_temp_dir("fetch-git-reuse-store");
    let cache_dir = unique_temp_dir("fetch-git-reuse-cache");
    let url = format!("file://{}", path_source(&repo_dir));
    let rev = oid.to_string();
    let source = fetch_git_metadata_source(&url, &rev);

    let first = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    let first_value: serde_json::Value =
        serde_json::from_slice(&first).expect("first fetchGit JSON parses");
    let out_path = first_value["pathValue"]
        .as_str()
        .expect("outPath is a string")
        .to_owned();
    assert!(
        Path::new(&out_path).join("data.txt").exists(),
        "first evaluation materializes the tree"
    );

    // Exactly one reuse record was written for the locked input.
    let records: Vec<_> = fs::read_dir(&cache_dir)
        .expect("reuse record directory exists after the first evaluation")
        .map(|entry| entry.expect("reuse record entry reads").path())
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one locked input, one record: {records:?}"
    );
    assert_eq!(
        records[0].extension().and_then(|ext| ext.to_str()),
        Some("json")
    );

    // Delete the source repository: a second evaluation can now only succeed
    // by answering from the reuse record — any clone attempt would fail.
    fs::remove_dir_all(&repo_dir).expect("repo temp directory removes");

    let second = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    assert_eq!(
        first, second,
        "reused result is byte-identical to the fetched one"
    );

    fs::remove_dir_all(&store_dir).expect("store temp directory removes");
    fs::remove_dir_all(&cache_dir).expect("cache temp directory removes");
}

#[test]
fn locked_fetch_git_record_is_not_trusted_without_the_store_path() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-reuse-gone");
    let store_dir = unique_temp_dir("fetch-git-reuse-gone-store");
    let cache_dir = unique_temp_dir("fetch-git-reuse-gone-cache");
    let url = format!("file://{}", path_source(&repo_dir));
    let rev = oid.to_string();
    let source = fetch_git_metadata_source(&url, &rev);

    let first = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    let first_value: serde_json::Value =
        serde_json::from_slice(&first).expect("first fetchGit JSON parses");
    let out_path = first_value["pathValue"]
        .as_str()
        .expect("outPath is a string")
        .to_owned();

    // Remove the materialized store path but keep the record and the repo:
    // the record alone must not satisfy the fetch, so the evaluator falls
    // through to a fresh clone and re-materializes the same result.
    fs::remove_dir_all(&out_path).expect("materialized store path removes");
    let second = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    assert_eq!(first, second, "fallthrough re-fetch reproduces the result");
    assert!(
        Path::new(&out_path).join("data.txt").exists(),
        "fallthrough re-materializes the tree"
    );

    fs::remove_dir_all(&repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(&store_dir).expect("store temp directory removes");
    fs::remove_dir_all(&cache_dir).expect("cache temp directory removes");
}

#[test]
fn unlocked_fetch_git_never_reuses_records() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-reuse-unlocked");
    let store_dir = unique_temp_dir("fetch-git-reuse-unlocked-store");
    let cache_dir = unique_temp_dir("fetch-git-reuse-unlocked-cache");
    let url = format!("file://{}", path_source(&repo_dir));
    let rev = oid.to_string();

    // A rev-pinned fetch seeds the record.
    let source = fetch_git_metadata_source(&url, &rev);
    let _ = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    fs::remove_dir_all(&repo_dir).expect("repo temp directory removes");

    // An unpinned fetch of the same URL must consult the repository, which is
    // gone — reuse records never answer rev-less (unlocked) fetches.
    let unlocked = format!(
        "(builtins.fetchGit {{ url = {url}; }}).rev",
        url = nix_string_literal(&url),
    );
    let error =
        eval_whnf_owned_with_options(&lower(&unlocked), reuse_options(&store_dir, &cache_dir))
            .expect_err("unlocked fetch must attempt the clone and fail");
    assert!(
        matches!(error.kind(), TreeWalkErrorKind::FetchGit { .. }),
        "unlocked fetch fails as a fetchGit error: {error:?}"
    );

    fs::remove_dir_all(&store_dir).expect("store temp directory removes");
    fs::remove_dir_all(&cache_dir).expect("cache temp directory removes");
}

#[test]
fn fetch_git_reuse_records_are_disabled_without_a_directory() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-reuse-off");
    let store_dir = unique_temp_dir("fetch-git-reuse-off-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = format!("file://{}", path_source(&repo_dir));
    let rev = oid.to_string();
    let source = fetch_git_metadata_source(&url, &rev);

    // No AOS_NIX_FETCH_GIT_CACHE, XDG_CACHE_HOME, or HOME is configured, so
    // no record is written anywhere and a repo-less re-evaluation fails.
    let _ = eval_json_bytes_with_options(&source, options.clone());
    fs::remove_dir_all(&repo_dir).expect("repo temp directory removes");
    // Select `outPath` so root WHNF evaluation forces the fetch itself.
    let forced = format!(
        r#"(builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}).outPath"#,
        url = nix_string_literal(&url),
    );
    let error = eval_whnf_owned_with_options(&lower(&forced), options)
        .expect_err("without a record directory the fetch must re-clone and fail");
    assert!(
        matches!(error.kind(), TreeWalkErrorKind::FetchGit { .. }),
        "repo-less re-fetch fails as a fetchGit error: {error:?}"
    );

    fs::remove_dir_all(&store_dir).expect("store temp directory removes");
}

#[test]
fn corrupt_fetch_git_reuse_records_fall_through_to_a_fresh_fetch() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-reuse-corrupt");
    let store_dir = unique_temp_dir("fetch-git-reuse-corrupt-store");
    let cache_dir = unique_temp_dir("fetch-git-reuse-corrupt-cache");
    let url = format!("file://{}", path_source(&repo_dir));
    let rev = oid.to_string();
    let source = fetch_git_metadata_source(&url, &rev);

    let first = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));

    // Truncate the record to invalid JSON: the next evaluation must ignore it,
    // re-fetch from the (still present) repository, and rewrite the record.
    let record = fs::read_dir(&cache_dir)
        .expect("reuse record directory exists")
        .map(|entry| entry.expect("reuse record entry reads").path())
        .next()
        .expect("one reuse record exists");
    fs::write(&record, b"{ corrupt").expect("record truncates");

    let second = eval_json_bytes_with_options(&source, reuse_options(&store_dir, &cache_dir));
    assert_eq!(first, second, "corrupt record falls through to a re-fetch");
    let rewritten = fs::read(&record).expect("record rereads");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&rewritten).is_ok(),
        "the re-fetch rewrites a well-formed record"
    );

    fs::remove_dir_all(&repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(&store_dir).expect("store temp directory removes");
    fs::remove_dir_all(&cache_dir).expect("cache temp directory removes");
}
