//! Tree-walk evaluator tests: fetchurl.

use super::*;

#[test]
fn placeholder_primop_requires_context_free_string_output() {
    let ir = lower("builtins.placeholder 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("placeholder argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("placeholder output must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"out".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing output allocates");

    let error = evaluator
        .eval_placeholder_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("placeholder rejects output string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "placeholder",
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        r#"builtins.placeholder (builtins.appendContext "out" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
    ))
    .expect_err("placeholder rejects context-bearing output expressions");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "placeholder",
            ..
        }
    ));
}

#[test]
fn path_literals_remain_paths_until_json_store_coercion() {
    let (dir, path) = temp_file_with_bytes("path-literal", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf {path}")),
        b"path"
    );
    assert_eq!(eval(&format!("builtins.isPath {path}")).as_bool(), Ok(true));
    assert_eq!(eval(&format!("{path} == {path}")).as_bool(), Ok(true));
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {path}")),
        br#""/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt""#
    );

    let ir = lower("./relative-file");
    let path_span = ir.arena.node(ir.root).expect("path exists").span;
    let error = eval_whnf_owned(&ir).expect_err("relative path literals need a source base");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: ir.root,
            path: b"./relative-file".to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn relative_path_literals_resolve_against_path_literal_base() {
    let dir = unique_temp_dir("relative-path-literals");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("./foo", options.clone()),
        base.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("../bar", options.clone()),
        dir.join("bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("foo/bar", options.clone()),
        base.join("foo/bar").as_os_str().as_bytes()
    );
    let mut expected_trace = b"trace: [ ".to_vec();
    expected_trace.extend_from_slice(base.join("foo").as_os_str().as_bytes());
    expected_trace.extend_from_slice(b" ]\n");
    assert_eq!(
        eval_captured_stderr_with_options("builtins.trace [ ./foo ] null", options.clone()),
        expected_trace
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf foo/bar", options),
        b"path"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn dot_slash_dot_resolves_to_path_literal_base() {
    let dir = unique_temp_dir("dot-slash-dot-path");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(dir.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("./.", options.clone()),
        dir.as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf ./.", options),
        b"path"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_literals_normalize_dot_and_parent_components() {
    let dir = unique_temp_dir("path-literal-normalization");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("foo/./bar", options.clone()),
        base.join("foo/bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("foo/../bar", options.clone()),
        base.join("bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("./foo/.", options.clone()),
        base.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("./foo/..", options),
        base.as_os_str().as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn absolute_path_literals_are_absolute_path_values() {
    assert_eq!(
        eval_path_bytes_with_options("/etc/foo", TreeWalkOptions::new()),
        b"/etc/foo"
    );
    assert_eq!(eval_string_bytes("builtins.typeOf /etc/foo"), b"path");
    assert_eq!(eval("builtins.isPath /etc/foo").as_bool(), Ok(true));
}

#[test]
fn home_relative_path_literals_use_configured_home_outside_pure_eval() {
    let dir = unique_temp_dir("home-relative-path-literals");
    let home = dir.join("home");
    let source_base = dir.join("source");
    fs::create_dir(&home).expect("home directory creates");
    fs::create_dir(&source_base).expect("source base directory creates");

    let mut options = TreeWalkOptions::with_home_dir(home.as_os_str().as_bytes().to_vec())
        .expect("home directory configures");
    options
        .set_path_literal_base(source_base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("~/foo", options.clone()),
        home.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf ~/foo", options.clone()),
        b"path"
    );
    assert_eq!(
        eval_with_options("builtins.isPath ~/foo", options).as_bool(),
        Ok(true)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn home_relative_path_literals_reject_pure_eval_and_missing_home() {
    let mut pure_options = TreeWalkOptions::with_home_dir(b"/tmp/aos-home".to_vec())
        .expect("home directory configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    let error = eval_whnf_owned_with_options(&lower("~/foo"), pure_options)
        .expect_err("pure evaluation rejects home path literals");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathNotAllowed {
            path,
            mode: EvalMode::Pure,
            ..
        } if path.as_slice() == b"~/foo"
    ));

    let error = eval_whnf_owned_with_options(&lower("~/foo"), TreeWalkOptions::new())
        .expect_err("home path literals need a configured home directory");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathUnavailable { path, .. }
            if path.as_slice() == b"~/foo"
    ));

    let options = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/tmp/aos-home".to_vec());
    let error = eval_whnf_owned_with_options(&lower("~/foo"), options)
        .expect_err("HOME environment configuration does not drive home path expansion");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathUnavailable { path, .. }
            if path.as_slice() == b"~/foo"
    ));
}

#[test]
fn relative_path_interpolation_resolves_against_path_literal_base() {
    let dir = unique_temp_dir("relative-path-interpolation");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${"b"}/c"#, options.clone()),
        base.join("a/b/c").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options(r#"builtins.typeOf (./a/${"b"}/c)"#, options.clone()),
        b"path"
    );
    assert_eq!(
        eval_with_options(r#"builtins.isPath (./a/${"b"}/c)"#, options.clone()).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${"../b"}/c"#, options.clone()),
        base.join("b/c").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${/x}/y"#, options),
        base.join("a/x/y").as_os_str().as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn slash_whitespace_disambiguates_division_from_path_literals() {
    let dir = unique_temp_dir("slash-path-disambiguation");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("1/2", options.clone()),
        base.join("1/2").as_os_str().as_bytes()
    );

    for source in ["1/ 2", "1 / 2", "1\t/\t2", "1\n/\n2", "1/*x*/ / 2"] {
        assert_eq!(
            eval_with_options(source, options.clone()).as_int(),
            Ok(0),
            "{source:?} should parse as integer division"
        );
    }

    let error = eval_whnf_owned_with_options(&lower("1 /2"), options.clone())
        .expect_err("whitespace before an absolute path parses as application");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));
    let error = eval_whnf_owned_with_options(&lower("1/**//2"), options)
        .expect_err("comment before an absolute path parses as application");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_interpolation_copies_sources_to_store_contexts() {
    let (dir, path) = temp_file_with_bytes("path-interpolation", b"abc");
    let path = path_source(&path);
    let store_path = "/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";
    let context_json = br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#;

    assert_eq!(
        eval_string_bytes(&format!("\"${{{path}}}\"")),
        store_path.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext \"${{{path}}}\")"
        )),
        context_json
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (builtins.toJSON {path}))"
        )),
        context_json
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (builtins.toString {path}))"
        )),
        b"{}"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON {{ nested = [ {{ path = {path}; }} ]; }}"
        )),
        br#"{"nested":[{"path":"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"}]}"#
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_coercion_context_is_observed_by_derivation_strict_as_input_src() {
    let (dir, path) = temp_file_with_bytes("path-context-input-src", b"abc");
    let path = path_source(&path);
    let source = format!(
        r#"let
                 d = derivationStrict {{
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   src = {path};
                 }};
               in {{
                 drvPath = d.drvPath;
                 out = d.out;
                 srcContext = builtins.getContext "${{{path}}}";
               }}"#
    );

    assert_eq!(
            eval_json_bytes(&source),
            br#"{"drvPath":"/nix/store/jwfqrwzg1mpqn9fc0x8g3ml72nisim2i-x.drv","out":"/nix/store/z6ky3vpva494v17vnc8xrzx6rv8nrycr-x","srcContext":{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}}"#.to_vec()
        );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_store_coercion_serializes_source_trees_and_symlinks() {
    let dir = unique_temp_dir("path-source-tree");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("data.txt"), b"abc").expect("tree file writes");
    std::os::unix::fs::symlink("data.txt", tree.join("link.txt")).expect("tree symlink creates");
    fs::write(dir.join("data.txt"), b"abc").expect("symlink target writes");
    let link = dir.join("link.txt");
    std::os::unix::fs::symlink("data.txt", &link).expect("temp symlink creates");
    let executable = dir.join("tool.sh");
    fs::write(&executable, b"abc").expect("executable file writes");
    let mut permissions = fs::metadata(&executable)
        .expect("executable file stats")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("executable mode sets");
    let tree = path_source(&tree);
    let link = path_source(&link);
    let executable = path_source(&executable);

    assert_eq!(
        eval_string_bytes(&format!("\"${{{tree}}}\"")),
        b"/nix/store/nl7y1ns16db5c34f34mlfizf6g3lxll3-tree"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {tree}")),
        br#""/nix/store/nl7y1ns16db5c34f34mlfizf6g3lxll3-tree""#
    );
    assert_eq!(
        eval_string_bytes(&format!("\"${{{link}}}\"")),
        b"/nix/store/r8q4lajdsk010slx81y3yc6zzclarwpl-link.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {link}")),
        br#""/nix/store/r8q4lajdsk010slx81y3yc6zzclarwpl-link.txt""#
    );
    assert_eq!(
        eval_string_bytes(&format!("\"${{{executable}}}\"")),
        b"/nix/store/4fgv55agm9sz9yxqvqbm8b5s483bmldn-tool.sh"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_primop_builds_source_store_paths_and_context() {
    let (dir, path) = temp_file_with_bytes("path-primop", b"abc");
    let path = path_source(&path);
    let store_path = b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";
    let renamed = b"/nix/store/lmv1fx64qbwh9yca6xv9a42fb3q3a1jx-renamed";

    assert_eq!(
        eval_string_bytes(&format!("builtins.path {{ path = {path}; }}")),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {}; }}",
            nix_string_literal(&path)
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.path; in p {{ path = {path}; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext (builtins.path {{ path = {path}; }})"
        )),
        br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#.to_vec()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_fetches_file_urls_and_records_context() {
    let (dir, path) = temp_file_with_bytes("fetchurl", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sri = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    let nix32 = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s";
    let store_path = b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt";
    let renamed = b"/nix/store/hy1mq1p855x9m96mxz4b9qaf1w0jjl5q-renamed";

    assert_eq!(
        eval_string_bytes(&format!("builtins.fetchurl {url}")),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{sri}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{nix32}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let fetchurl = builtins.fetchurl; in fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext (builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }})"
        )),
        br#"{"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt":{"path":true}}"#.to_vec()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.readFile p"
        )),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.hashFile \"sha256\" p"
        )),
        digest.as_bytes()
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in [ (builtins.pathExists p) (builtins.readFileType p) ]"
        )),
        br#"[true,"regular"]"#.to_vec()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_uses_raw_url_basename_for_default_name() {
    let (dir, path) = temp_file_with_bytes("fetchurl-query", b"abc");
    let url = format!("file://{}?foo=bar", path_source(&path));
    let url = nix_string_literal(&url);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
        )),
        b"/nix/store/cnsr0sbn6xzksm6fa7dh81a1d2yxx0fk-data.txt?foo=bar"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_invalid_arguments() {
    let (dir, path) = temp_file_with_bytes("fetchurl-invalid", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("hash mismatch rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"\"; }}"
    ));
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator
        .eval_root()
        .expect_err("empty fetchurl hash warns and then mismatches real content");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { expected, .. }
            if expected.as_slice() == [0_u8; 32]
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        EMPTY_FETCHURL_SHA256_WARNING,
    );

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; bogus = 1; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchurl attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchUrlAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(
        r#"builtins.fetchurl { sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
    );
    let error = eval_whnf_owned(&ir).expect_err("missing url rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; name = \"bad/name\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid store name rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlStoreName { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_obeys_eval_mode_gates() {
    let (dir, path) = temp_file_with_bytes("fetchurl-mode", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let source = format!("builtins.fetchurl {url}");

    let error = eval_whnf_owned_with_options(
        &lower(&source),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchurl before URL access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        ),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchurl { url = "https://cache.example/data.txt"; sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted eval rejects disallowed network fetchurl before network access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_fetches_http_urls_as_identity_bytes() {
    let (url, body_hash, handle) = gzip_encoded_http_fixture("/data.txt", b"abc");
    let url = nix_string_literal(&url);
    let store_dir = unique_temp_dir("fetchurl-http-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"
                let p = builtins.fetchurl {{
                  url = {url};
                  name = "http-identity-data";
                  sha256 = "{body_hash}";
                }};
                in builtins.hashFile "sha256" p
                "#
            ),
            options,
        ),
        body_hash.as_bytes()
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");

    assert_http_fixture_requested_identity(
        handle.join().expect("HTTP fixture thread completes"),
        "fetchurl",
    );
}

#[test]
fn fetchurl_primop_reuses_materialized_fixed_output_paths_before_fetching() {
    let (dir, path) = temp_file_with_bytes("fetchurl-reuse", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = String::from_utf8(eval_string_bytes(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"cached\"; }}"
    )))
    .expect("store paths are UTF-8");

    let pure_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let pure_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    assert_eq!(
        eval_json_bytes_with_options(&pure_source, pure_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    let restricted_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://cache.example/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut restricted_options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_path(path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");
    restricted_options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        eval_json_bytes_with_options(&restricted_source, restricted_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_reuse_through_restricted_file_url_policy() {
    let (allowed_dir, allowed_path) = temp_file_with_bytes("fetchurl-allowed", b"abc");
    let (blocked_dir, blocked_path) = temp_file_with_bytes("fetchurl-blocked", b"abc");
    let allowed_path = path_source(&allowed_path);
    let blocked_path = path_source(&blocked_path);
    let allowed_url = nix_string_literal(&format!("file://{allowed_path}"));
    let blocked_url = nix_string_literal(&format!("file://{blocked_path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let source = format!(
        r#"builtins.toJSON [
              (builtins.fetchurl {{ url = {allowed_url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = {blocked_url}; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed_path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("restricted file URL policy is checked before fixed-output reuse");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path,
            mode: EvalMode::Restricted,
            ..
        } if path.as_slice() == blocked_path.as_bytes()
    ));

    fs::remove_dir_all(allowed_dir).expect("allowed temp directory removes");
    fs::remove_dir_all(blocked_dir).expect("blocked temp directory removes");
}

#[test]
fn fetchurl_primop_reuses_existing_configured_store_paths() {
    let store_dir = unique_temp_dir("fetchurl-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let (source_dir, source_path) = temp_file_with_bytes("fetchurl-existing-store", b"abc");
    let source_url = nix_string_literal(&format!("file://{}", path_source(&source_path)));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = eval_string_bytes_with_options(
        &format!(
            r#"builtins.fetchurl {{ url = {source_url}; sha256 = "{digest}"; name = "cached"; }}"#
        ),
        options.clone(),
    );
    let expected_path_text = std::str::from_utf8(&expected_path)
        .expect("store path is UTF-8")
        .to_owned();
    let expected_path_buf = PathBuf::from(expected_path_text.clone());
    fs::create_dir_all(
        expected_path_buf
            .parent()
            .expect("store path has parent directory"),
    )
    .expect("store directory creates");
    fs::write(&expected_path_buf, b"abc").expect("existing store path writes");
    options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }}"#
            ),
            options,
        ),
        expected_path,
    );

    fs::remove_dir_all(source_dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
