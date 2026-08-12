//! Tree-walk test support: C++ Nix builtin-family oracle helpers.

use super::super::*;
use super::*;

pub(crate) fn assert_cpp_nix_filesystem_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let root = fs::canonicalize(unique_temp_dir("filesystem-builtins"))
        .expect("temp directory canonicalizes");
    let regular = root.join("regular.txt");
    let nested = root.join("nested");
    let link = root.join("link");
    let link_dir = root.join("link-dir");
    let dangling = root.join("dangling");
    fs::write(&regular, b"hello\n").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("file symlink creates");
    std::os::unix::fs::symlink(&nested, &link_dir).expect("directory symlink creates");
    std::os::unix::fs::symlink(root.join("missing-target"), &dangling)
        .expect("dangling symlink creates");

    let root_source = nix_string_literal(&path_source(&root));
    let regular_path = path_source(&regular);
    let regular_source = nix_string_literal(&regular_path);
    let nested_source = nix_string_literal(&path_source(&nested));
    let link_source = nix_string_literal(&path_source(&link));
    let link_dir_path = path_source(&link_dir);
    let link_dir_source = nix_string_literal(&link_dir_path);
    let dangling_path = path_source(&dangling);
    let dangling_source = nix_string_literal(&dangling_path);
    let missing_source = nix_string_literal(&path_source(&root.join("missing")));

    for source in [
        format!("builtins.readFile {regular_source}"),
        format!("builtins.readFile {regular_path}"),
        format!(r#"let f = builtins.readFile; in f {link_source}"#),
        format!("builtins.hasContext (builtins.readFile {regular_source})"),
        format!("builtins.readDir {root_source}"),
        format!("builtins.attrNames (builtins.readDir {root_source})"),
        format!("builtins.readFileType {regular_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/."))
        ),
        format!("builtins.readFileType {nested_source}"),
        format!("builtins.readFileType {link_source}"),
        format!("builtins.readFileType {link_dir_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        ),
        format!("builtins.readFileType {dangling_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/."))
        ),
        format!("builtins.pathExists {regular_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{regular_path}/."))
        ),
        format!("builtins.pathExists {nested_source}"),
        format!("builtins.pathExists {link_dir_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        ),
        format!("builtins.pathExists {dangling_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dangling_path}/"))
        ),
        format!("builtins.pathExists {missing_source}"),
        format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{regular_path}/"))
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

pub(crate) fn assert_cpp_nix_find_file_and_search_path_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    let (root, nixpkgs, subdir) = search_path_fixture();
    let nixpkgs_source = nix_string_literal(&path_source(&nixpkgs));
    let root_source = nix_string_literal(&path_source(&root));
    let expected = path_source(&subdir);

    for source in [
        format!(
            r#"let p = builtins.findFile [ {{ path = {nixpkgs_source}; prefix = "nixpkgs"; }} ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
        format!(
            r#"let p = builtins.findFile [ {{ path = {nixpkgs_source}; }} ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
        format!(
            r#"let p = builtins.findFile [ {{ path = {root_source}; prefix = ""; }} ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let nix_path = format!("nixpkgs={}", path_source(&nixpkgs));
    let options = search_path_options(b"nixpkgs", &nixpkgs);
    for source in [
        r#"builtins.head builtins.nixPath"#,
        r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
        r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk_with_options_and_env(
            oracle,
            source,
            options.clone(),
            &[("NIX_PATH", &nix_path)],
        );
    }

    let actual = eval_string_bytes_with_options(
        r#"builtins.toString <nixpkgs/subdir>"#,
        search_path_options(b"nixpkgs", &nixpkgs),
    );
    assert_eq!(actual, expected.into_bytes());
}

pub(crate) fn assert_cpp_nix_json_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.fromJSON ''{"b":1,"a":[true,false,null,"x"],"c":{"n":2.5}}''"#,
        r#"builtins.attrNames (builtins.fromJSON ''{"b":1,"a":2}'')"#,
        r#"(builtins.fromJSON ''{"a":1,"a":2}'').a"#,
        r#"builtins.fromJSON ''"é"''"#,
        r#"builtins.fromJSON "9223372036854775808""#,
        r#"builtins.fromJSON "18446744073709551615""#,
        r#"builtins.typeOf (builtins.fromJSON "-9223372036854775809")"#,
        r#"builtins.hasContext (builtins.fromJSON ''"x"'')"#,
        r#"let f = builtins.fromJSON; in f "{}""#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        "null",
        "true",
        "false",
        "42",
        r#""é""#,
        r#""\t\r\n\\\"""#,
        r#"builtins.fromJSON "\"\\b\"""#,
        r#"builtins.fromJSON "\"\\f\"""#,
        r#"builtins.fromJSON "\"\\u0001\"""#,
        r#"builtins.fromJSON "\"\\u001f\"""#,
        r#"{ b = 1; a = [ true false null "x" ]; }"#,
        r#"{ "10" = 10; "2" = 2; A = 1; a = 2; }"#,
        "1.0",
        "1.50",
        "(-0.0)",
        "0.000001",
        "100000000000000000000.0",
        "((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))",
        "(1.0e308 * 1.0e308)",
        r#"{ __toString = self: "hook"; outPath = "out"; }"#,
        r#"{ __toString = self: { outPath = "nested"; }; }"#,
        r#"{ outPath = [ "a" "b" ]; }"#,
        r#"{ outPath = "out"; a = 1; }"#,
        "{}",
    ] {
        assert_cpp_nix_to_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.fromJSON "01""#,
        "builtins.fromJSON 1",
        "builtins.toJSON [ (x: x) ]",
        "builtins.toJSON [ 1 (1 / 0) ]",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_xml_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"{ a = 1; b = [ true false null "x<y&\"z" ]; }"#,
        r#""a
<&>\"b""#,
        r#"[ 1.25 (-0.0) 0.000001 1000000.0 100000000000000000000.0 1.23456789 1234567.0 ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) (1.0e308 * 1.0e308) (builtins.sub 0.0 (1.0e308 * 1.0e308)) ]"#,
        "x: x",
        "{ a, b ? 1, ... }: a",
        "args@{ a, ... }: a",
        "builtins.length",
        r#"{ type = "derivation"; drvPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv"; outPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x"; name = "x"; }"#,
        r#"{ type = "derivation"; drvPath = 1; outPath = 2; }"#,
        r#"[
                (builtins.appendContext "direct" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-direct" = { path = true; };
                })
            ]"#,
    ] {
        assert_cpp_nix_to_xml_matches_tree_walk(oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_hash_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.hashString "md5" "abc""#,
        r#"builtins.hashString "sha1" "abc""#,
        r#"builtins.hashString "sha256" "abc""#,
        r#"builtins.hashString "sha512" "abc""#,
        r#"let h = builtins.hashString "sha256"; in h "abc""#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base64"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "nix32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "sri"; }"#,
        r#"builtins.convertHash { hash = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "md5" "abc"; hashAlgo = "md5"; toHashFormat = "nix32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha1" "abc"; hashAlgo = "sha1"; toHashFormat = "base64"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha512" "abc"; hashAlgo = "sha512"; toHashFormat = "nix32"; }"#,
        r#"let convert = builtins.convertHash; in convert { hash = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.placeholder "out""#,
        r#"builtins.placeholder "dev""#,
        r#"let placeholder = builtins.placeholder; in placeholder "out""#,
        r#"builtins.stringLength (builtins.placeholder "out")"#,
        r#"let p = builtins.toFile "foo" "bar"; in { path = p; ctx = builtins.getContext p; }"#,
        r#"let p = builtins.toFile "foo" "bar"; nested = builtins.toFile "baz" p; in { nested = nested; nestedCtx = builtins.getContext nested; }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    let (dir, path) = temp_file_with_bytes("cpp-nix-hash-file", b"abc");
    let path = path_source(&path);
    for source in [
        format!(r#"builtins.hashFile "md5" {path}"#),
        format!(r#"builtins.hashFile "sha1" {path}"#),
        format!(r#"builtins.hashFile "sha256" {path}"#),
        format!(
            r#"builtins.hashFile "sha512" {}"#,
            nix_string_literal(&path)
        ),
        format!(
            r#"builtins.hashFile "sha256" {{ outPath = {}; }}"#,
            nix_string_literal(&path)
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let recursive_digest = "11a71b4754d812f4aea20161c533bdaa112ac5c853013e65d3aa9640b5735230";
    let flat_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let file_url = nix_string_literal(&format!("file://{path}"));
    for source in [
        format!("builtins.path {{ path = {path}; }}"),
        format!("builtins.path {{ path = {}; }}", nix_string_literal(&path)),
        format!("builtins.path {{ path = {path}; name = \"renamed\"; }}"),
        format!("let p = builtins.path; in p {{ path = {path}; name = \"renamed\"; }}"),
        format!("builtins.path {{ path = {path}; recursive = false; }}"),
        format!("builtins.path {{ path = {path}; sha256 = \"{recursive_digest}\"; }}"),
        format!(
            "builtins.path {{ path = {path}; recursive = false; sha256 = \"{flat_digest}\"; }}"
        ),
        format!(
            "builtins.path {{ path = {path}; recursive = false; filter = path: type: builtins.throw \"called\"; }}"
        ),
        format!("builtins.fetchurl {file_url}"),
        format!("builtins.fetchurl {{ url = {file_url}; sha256 = \"{flat_digest}\"; }}"),
        format!(
            "let fetchurl = builtins.fetchurl; in fetchurl {{ url = {file_url}; sha256 = \"{flat_digest}\"; name = \"renamed\"; }}"
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("oracle tree directory creates");
    fs::write(tree.join("a"), b"one").expect("oracle included file writes");
    fs::write(tree.join("b"), b"two").expect("oracle excluded file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.hasContext path == false && builtins.baseNameOf path == "a""#;
    for source in [
        format!("builtins.filterSource ({keep}) {tree}"),
        format!("builtins.path {{ path = {tree}; filter = ({keep}); }}"),
        format!("let filterSource = builtins.filterSource; in filterSource ({keep}) {tree}"),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }
    fs::remove_dir_all(dir).expect("temp directory removes");

    for source in [
        r#"builtins.hashString "sha384" "abc""#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = null; toHashFormat = "base16"; }"#,
        r#"builtins.placeholder 1"#,
        r#"builtins.placeholder (builtins.appendContext "out" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; })"#,
        r#"builtins.toFile "bad/name" "x""#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_json(oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_flake_ref_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.parseFlakeRef "github:NixOS/nixpkgs?%64ir=lib""#,
        r#"builtins.parseFlakeRef "file+https://example.com/blob.txt?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D""#,
        r#"builtins.parseFlakeRef "https://example.com/source.tar.gz?revCount=bad&lastModified=nope&foo=bar""#,
        r#"builtins.flakeRefToString {
                narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                owner = "NixOS";
                repo = "nixpkgs";
                rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                type = "github";
            }"#,
        r#"builtins.flakeRefToString {
                rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                type = "git";
                url = "https://example.com/repo";
            }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                rev = "bad";
            }"#,
        r#"builtins.flakeRefToString {
                type = "tarball";
                url = "https://example.com/source.tar.gz";
                narHash = "not-a-hash";
            }"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_json(oracle, source);
    }
}
