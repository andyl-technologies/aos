//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn fetch_tree_forge_direct_attrsets_reject_last_modified_mismatch() {
    fn current_unix_seconds() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_secs(),
        )
        .expect("current Unix time fits in Nix int")
    }

    fn append_future_tar_bytes<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        path: &str,
        mode: u32,
        bytes: &[u8],
        mtime: i64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("tar path is valid");
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(u64::try_from(mtime).expect("test mtime is non-negative"));
        header.set_cksum();
        builder
            .append(&header, bytes)
            .expect("tar fixture entry appends");
    }

    let future_last_modified = current_unix_seconds()
        .checked_add(31_536_000)
        .expect("future test mtime fits in Nix int");
    let archive_dir = unique_temp_dir("fetch-tree-forge-metadata");
    let archive_path = archive_dir.join("root.tar.gz");
    let file = fs::File::create(&archive_path).expect("tarball fixture creates");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_future_tar_bytes(
        &mut builder,
        "root/file.txt",
        0o644,
        b"data",
        future_last_modified,
    );
    append_future_tar_bytes(
        &mut builder,
        "root/sub/nested.txt",
        0o644,
        b"inner",
        future_last_modified,
    );
    let encoder = builder.into_inner().expect("tar fixture finalizes");
    encoder.finish().expect("gzip fixture finalizes");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-forge-metadata-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let rev = "0123456789abcdef0123456789abcdef01234567";

    for archive_url in [
        format!("https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz"),
        format!(
            "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}"
        ),
        format!("https://git.sr.ht/~andyl/aos/archive/{rev}.tar.gz"),
    ] {
        options.add_fetch_tree_url_response(archive_url, archive_bytes.clone());
    }

    for (input_type, owner, repo) in [
        ("github", "NixOS", "nixpkgs"),
        ("gitlab", "NixOS", "nixpkgs"),
        ("sourcehut", "~andyl", "aos"),
    ] {
        let json = eval_json_bytes_with_options(
            &format!(
                r#"
                    let x = builtins.fetchTree {{
                      type = "{input_type}";
                      owner = "{owner}";
                      repo = "{repo}";
                      rev = "{rev}";
                    }};
                    in {{ lastModified = x.lastModified; rev = x.rev; }}
                    "#
            ),
            options.clone(),
        );
        let value: serde_json::Value =
            serde_json::from_slice(&json).expect("forge metadata JSON parses");
        assert_eq!(value["rev"], rev, "{input_type}");
        let observed_last_modified = value["lastModified"]
            .as_i64()
            .expect("lastModified is an integer");
        assert_eq!(observed_last_modified, future_last_modified, "{input_type}");
        let wrong_last_modified = future_last_modified
            .checked_add(31_536_000)
            .expect("wrong test mtime fits in Nix int");

        let error = eval_whnf_owned_with_options(
            &lower(&format!(
                r#"builtins.fetchTree {{
                      type = "{input_type}";
                      owner = "{owner}";
                      repo = "{repo}";
                      rev = "{rev}";
                      lastModified = {wrong_last_modified};
                    }}"#
            )),
            options.clone(),
        )
        .expect_err("direct forge fetchTree rejects mismatched lastModified");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
                    expected,
                    actual,
                    ..
                } if expected == wrong_last_modified && actual == future_last_modified
            ),
            "{input_type}: {error:?}",
        );
    }

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_validates_input_shape() {
    let dir = unique_temp_dir("fetch-tree-invalid");
    fs::write(dir.join("data.txt"), b"data").expect("source file writes");
    let path = nix_string_literal(&path_source(&dir));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ type = "path"; path = {path}; bogus = 1; }}"#
    )))
    .expect_err("unknown fetchTree attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ type = "path"; path = {path}; name = "bad"; }}"#
    )))
    .expect_err("fetchTree rejects name attr");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeAttr { attr, .. }
            if attr.as_slice() == b"name"
    ));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ path = {path}; }}"#
    )))
    .expect_err("fetchTree requires type attr");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; }"#,
    ))
    .expect_err("unresolved forge fetchTree rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge inputs without a resolved rev",
            ..
        }
    ));

    for (source, expected_uri) in [
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; }"#,
                b"github:NixOS/nixpkgs".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; dir = "lib"; }"#,
                b"github:NixOS/nixpkgs/main".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; dir = "lib"; narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }"#,
                b"github:NixOS/nixpkgs/main?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = ""; }"#,
                b"github:NixOS/nixpkgs/".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "bad?ref"; }"#,
                b"github:NixOS/nixpkgs/bad%3Fref".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = ""; repo = "nixpkgs"; }"#,
                b"github:/nixpkgs".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "gitlab"; owner = "group"; repo = "project/private"; }"#,
                b"gitlab:group/project/private".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; host = "bad host"; }"#,
                b"github:NixOS/nixpkgs".as_slice(),
            ),
        ] {
            let error = eval_whnf_owned_with_options(
                &lower(source),
                TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
            )
            .expect_err("restricted unresolved forge attrset denies its canonical URI");
            assert!(matches!(
                error.kind(),
                TreeWalkErrorKind::FetchTreeAccessDenied {
                    input,
                    mode: EvalMode::Restricted,
                    ..
                } if input == expected_uri
            ));
        }

    for source in [
        r#"builtins.fetchTree { type = "sourcehut"; owner = "~andyl"; repo = "aos"; ref = ""; }"#,
        r#"builtins.fetchTree { type = "sourcehut"; owner = "~andyl"; repo = "aos"; ref = "bad?ref"; }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("invalid sourcehut ref attrset rejects before fetching");
        assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));
    }

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = true; }"#,
        ))
        .expect_err("unsupported fetchTree verified git fetch rejects before repo access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "verified git fetches",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = false; publicKey = 1; }"#,
        ))
        .expect_err("fetchTree publicKey must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = false; publicKeys = [ { key = 1; type = "ssh-ed25519"; } ]; }"#,
        ))
        .expect_err("fetchTree publicKeys entries must carry string keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchTree {
                 type = "git";
                 url = "file:///no-such-repo";
                 verifyCommit = false;
                 publicKeys = [
                   (builtins.foldl' (acc: _x: acc) { key = 1; type = "ssh-ed25519"; } [])
                 ];
               }"#,
    ))
    .expect_err("fetchTree publicKeys lazy foldl entries are forced before field checks");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.fetchTree "github:NixOS/nixpkgs""#))
        .expect_err("unsupported string flake ref type rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge inputs without a resolved rev",
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}
