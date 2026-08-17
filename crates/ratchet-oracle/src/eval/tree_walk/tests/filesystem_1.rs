//! Tree-walk evaluator tests: filesystem 1.

use super::*;
use sha2::{Digest, Sha256};

#[test]
fn hash_file_primop_hashes_file_contents() {
    let (dir, path) = temp_file_with_bytes("hash-file", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"md5\" {path}")),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"sha1\" {path}")),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"sha256\" {path}")),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"sha512\" {path}")),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.hashFile \"sha256\" {}",
            nix_string_literal(&path)
        )),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.hashFile \"sha256\" {{ outPath = {}; }}",
            nix_string_literal(&path)
        )),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.hashFile "sha256" (builtins.toFile "x" "abc")"#),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashFile = type: path: \"local\"; }; in builtins.hashFile \"sha256\" \"relative.txt\""
        ),
        b"local"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn source_path_sha_helpers_return_nix_sha256_digests() {
    let (dir, path) = temp_file_with_bytes("source-sha-domain", b"abc");
    let ir = lower("null");
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let flat: NixSha256Digest = evaluator
        .source_path_flat_sha256(ir.root, root_span, &path)
        .expect("flat source SHA-256 computes");
    let mut expected_flat = [0_u8; 32];
    expected_flat.copy_from_slice(&Sha256::digest(b"abc"));
    assert_eq!(flat, NixSha256Digest::from_bytes(expected_flat));

    let nar: NixSha256Digest = evaluator
        .source_path_nar_sha256(ir.root, root_span, &path, None)
        .expect("recursive source NAR SHA-256 computes");
    assert_ne!(nar, flat);
    assert!(
        evaluator
            .fetch_tarball_store_path_matches_digest(
                ir.root,
                root_span,
                path.as_os_str().as_bytes(),
                nar
            )
            .expect("typed fetchTarball digest match checks")
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn hash_file_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashFile \"sha256\" ./crates/Cargo.toml");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashFile")
        .expect_err("hashFile rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashFile",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_file_primop_checks_algorithm_before_path() {
    let ir = lower("builtins.hashFile \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let error = eval_whnf_owned(&lower("builtins.hashFile \"sha256\" (1 / 0)"))
        .expect_err("valid algorithm demands path argument");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn hash_file_primop_rejects_relative_strings() {
    let ir = lower("builtins.hashFile \"sha256\" \"relative.txt\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path = args[1];
    let path_span = ir.arena.node(path).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: path,
            path: b"relative.txt".to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);
}

#[test]
fn hash_file_primop_reports_file_read_errors() {
    let dir = unique_temp_dir("hash-file-missing");
    let path = path_source(&dir.join("missing.txt"));
    let ir = lower(&format!(
        "builtins.hashFile \"sha256\" {}",
        nix_string_literal(&path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path_id = args[1];
    let path_span = ir.arena.node(path_id).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing file is reported");

    match error.kind() {
        TreeWalkErrorKind::FileRead {
            id,
            path: actual,
            message,
        } => {
            assert_eq!(id, path_id);
            assert_eq!(actual.as_slice(), path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected file-read error, got {other:?}"),
    }
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_unallowed_filesystem_reads() {
    let (dir, path) = temp_file_with_bytes("fs-policy-denied", b"abc");
    let path = path_source(&path);
    let source = format!("builtins.readFile {}", nix_string_literal(&path));
    let ir = lower(&source);
    let (argument, argument_span) = primop_argument(&ir, 0);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed reads");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            id: argument,
            path: path.as_bytes().to_vec(),
            mode: EvalMode::Restricted,
        }
    );
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_allows_configured_roots() {
    let dir = unique_temp_dir("fs-policy-allowed");
    let regular = dir.join("regular.txt");
    fs::write(&regular, b"abc").expect("regular file writes");
    let dir_path = path_source(&dir);
    let file_path = path_source(&regular);
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(dir.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!("builtins.readFile {}", nix_string_literal(&file_path)),
            options.clone(),
        ),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.hashFile \"sha256\" {}",
                nix_string_literal(&file_path)
            ),
            options.clone(),
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            &format!("builtins.readFileType {}", nix_string_literal(&file_path)),
            options.clone(),
        ),
        b"regular"
    );
    assert_eq!(
        eval_list_string_bytes_with_options(
            &format!(
                "builtins.attrNames (builtins.readDir {})",
                nix_string_literal(&dir_path)
            ),
            options.clone(),
        ),
        vec![b"regular.txt".to_vec()]
    );
    assert_eq!(
        eval_with_options(
            &format!("builtins.pathExists {}", nix_string_literal(&file_path)),
            options,
        )
        .as_bool(),
        Ok(true)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_normalizes_paths_before_matching() {
    let base = unique_temp_dir("fs-policy-normalized");
    let allowed = base.join("allowed");
    let sibling = base.join("allowed-sibling");
    fs::create_dir(&allowed).expect("allowed directory creates");
    fs::create_dir(&sibling).expect("sibling directory creates");
    fs::write(allowed.join("data.txt"), b"allowed").expect("allowed file writes");
    fs::write(sibling.join("data.txt"), b"denied").expect("sibling file writes");
    let allowed_path = path_source(&allowed);
    let allowed_with_parent = format!("{allowed_path}/../allowed/data.txt");
    let sibling_path = path_source(&sibling.join("data.txt"));
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.readFile {}",
                nix_string_literal(&allowed_with_parent)
            ),
            options.clone(),
        ),
        b"allowed"
    );

    let source = format!("builtins.readFile {}", nix_string_literal(&sibling_path));
    let ir = lower(&source);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("sibling prefix is not under the allowed root");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_resolved_symlink_escapes() {
    let base = unique_temp_dir("fs-policy-symlink");
    let allowed = base.join("allowed");
    let outside = base.join("outside.txt");
    let link = allowed.join("link.txt");
    fs::create_dir(&allowed).expect("allowed directory creates");
    fs::write(&outside, b"outside").expect("outside file writes");
    std::os::unix::fs::symlink(&outside, &link).expect("escape symlink creates");
    let link_path = path_source(&link);
    let outside_path = fs::canonicalize(&outside).expect("outside path resolves");
    let outside_path = normalize_absolute_path_bytes(outside_path.as_os_str().as_bytes());
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    let source = format!("builtins.readFile {}", nix_string_literal(&link_path));
    let ir = lower(&source);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("symlink escapes outside allowed roots are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            id: primop_argument(&ir, 0).0,
            path: outside_path,
            mode: EvalMode::Restricted,
        }
    );

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_gates_find_file_candidates() {
    let base = unique_temp_dir("fs-policy-find-file");
    let root = base.join("nixpkgs");
    fs::create_dir(&root).expect("search root creates");
    fs::write(root.join("default.nix"), b"{ }").expect("search file writes");
    let root_path = path_source(&root);
    let source = format!(
        r#"builtins.typeOf (builtins.findFile [ {{ prefix = "nixpkgs"; path = {}; }} ] "nixpkgs/default.nix")"#,
        nix_string_literal(&root_path)
    );
    let ir = lower(&source);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed findFile candidates");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(root.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");
    assert_eq!(eval_string_bytes_with_options(&source, options), b"path");

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_source_path_serialization() {
    let (dir, path) = temp_file_with_bytes("fs-policy-source-path", b"abc");
    let path_source = path_source(&path);
    let source = format!("\"${{{path_source}}}\"");
    let ir = lower(&source);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed source path serialization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(dir.as_os_str().as_bytes().to_vec())
        .expect("allowed source root configures");
    assert_eq!(
        eval_string_bytes_with_options(&source, options),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_exists_primop_checks_filesystem_presence() {
    let dir = unique_temp_dir("path-exists");
    let file = dir.join("regular.txt");
    let dangling = dir.join("dangling");
    fs::write(&file, b"data").expect("regular file writes");
    std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
        .expect("dangling symlink creates");
    let dir_path = path_source(&dir);
    let file_path = path_source(&file);
    let dangling_path = path_source(&dangling);
    let missing_path = path_source(&dir.join("missing.txt"));

    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&file_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&missing_path)
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&dangling_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dangling_path}/"))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dir_path}/"))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{file_path}/"))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{file_path}/."))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{file_path}/"))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{file_path}/."))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "let f = builtins.pathExists; in f {}",
            nix_string_literal(&file_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let builtins = { pathExists = path: false; }; in builtins.pathExists \"/\"")
            .as_bool(),
        Ok(false)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_exists_primop_records_impure_input_trace_with_mode() {
    let dir = unique_temp_dir("path-exists-trace");
    let file = dir.join("regular.txt");
    fs::write(&file, b"data").expect("regular file writes");
    let file_path = path_source(&file);
    let directory_required_path = format!("{file_path}/");

    let existing = eval_whnf_owned(&lower(&format!(
        "builtins.pathExists {}",
        nix_string_literal(&file_path)
    )))
    .expect("source evaluates");
    let existing_expected = vec![
        ImpureInputFingerprint::path_exists(file_path.as_bytes(), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(existing.value().as_bool(), Ok(true));
    assert_eq!(existing.impure_input_trace(), existing_expected.as_slice());

    let directory_required = eval_whnf_owned(&lower(&format!(
        "builtins.pathExists {}",
        nix_string_literal(&directory_required_path)
    )))
    .expect("source evaluates");
    let directory_required_expected = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            directory_required_path.as_bytes(),
            ImpureInputMode::RequireDirectory,
            false,
        )
        .expect("fingerprint builds"),
    ];
    assert_eq!(directory_required.value().as_bool(), Ok(false));
    assert_eq!(
        directory_required.impure_input_trace(),
        directory_required_expected.as_slice()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_exists_primop_type_checks_and_rejects_relative_strings() {
    let ir = lower("builtins.pathExists 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("pathExists requires a path");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.pathExists \"relative.txt\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: argument,
            path: b"relative.txt".to_vec(),
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn read_file_type_primop_reports_filesystem_node_types() {
    let dir = unique_temp_dir("read-file-type");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    let link = dir.join("link");
    let link_dir = dir.join("link-dir");
    let dangling = dir.join("dangling");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
    std::os::unix::fs::symlink(&nested, &link_dir).expect("directory symlink creates");
    std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
        .expect("dangling symlink creates");
    let regular_path = path_source(&regular);
    let nested_path = path_source(&nested);
    let link_path = path_source(&link);
    let link_dir_path = path_source(&link_dir);
    let dangling_path = path_source(&dangling);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&regular_path)
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&nested_path)
        )),
        b"directory"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&link_path)
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/"))
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/."))
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/."))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/"))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/."))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let f = builtins.readFileType; in f {}",
            nix_string_literal(&regular_path)
        )),
        b"regular"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_type_primop_records_impure_input_trace() {
    let (dir, path) = temp_file_with_bytes("read-file-type-trace", b"data");
    let path = path_source(&path);
    let outcome = eval_whnf_owned(&lower(&format!(
        "builtins.readFileType {}",
        nix_string_literal(&path)
    )))
    .expect("source evaluates");
    let expected = vec![
        ImpureInputFingerprint::read_file_type(path.as_bytes(), FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];

    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_type_primop_reports_stat_errors() {
    let dir = unique_temp_dir("read-file-type-missing");
    let missing_path = path_source(&dir.join("missing"));
    let ir = lower(&format!(
        "builtins.readFileType {}",
        nix_string_literal(&missing_path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing path is reported");

    match error.kind() {
        TreeWalkErrorKind::PathStat { id, path, message } => {
            assert_eq!(id, argument);
            assert_eq!(path.as_slice(), missing_path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected stat error, got {other:?}"),
    }
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_dir_primop_lists_entry_types() {
    let dir = unique_temp_dir("read-dir");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    let link = dir.join("link");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
    let dir_path = path_source(&dir);

    assert_eq!(
        eval_list_string_bytes(&format!(
            "builtins.attrNames (builtins.readDir {})",
            nix_string_literal(&dir_path)
        )),
        vec![b"link".to_vec(), b"nested".to_vec(), b"regular".to_vec()]
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).link",
            nix_string_literal(&dir_path)
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).nested",
            nix_string_literal(&dir_path)
        )),
        b"directory"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).regular",
            nix_string_literal(&dir_path)
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let f = builtins.readDir; d = f {}; in d.regular",
            nix_string_literal(&dir_path)
        )),
        b"regular"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_dir_primop_records_impure_input_trace() {
    let dir = unique_temp_dir("read-dir-trace");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    let link = dir.join("link");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
    let dir_path = path_source(&dir);

    let outcome = eval_whnf_owned(&lower(&format!(
        "builtins.readDir {}",
        nix_string_literal(&dir_path)
    )))
    .expect("source evaluates");
    let expected = vec![
        ImpureInputFingerprint::read_dir(
            dir_path.as_bytes(),
            [
                DirEntryInput::new(b"regular", FileTypeForInput::Regular),
                DirEntryInput::new(b"nested", FileTypeForInput::Directory),
                DirEntryInput::new(b"link", FileTypeForInput::Symlink),
            ],
        )
        .expect("fingerprint builds"),
    ];

    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_dir_primop_type_checks_and_reports_directory_errors() {
    let ir = lower("builtins.readDir 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("readDir requires a path");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let dir = unique_temp_dir("read-dir-file");
    let regular = dir.join("regular");
    fs::write(&regular, b"data").expect("regular file writes");
    let regular_path = path_source(&regular);
    let ir = lower(&format!(
        "builtins.readDir {}",
        nix_string_literal(&regular_path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("file is not a directory");

    match error.kind() {
        TreeWalkErrorKind::DirectoryRead { id, path, message } => {
            assert_eq!(id, argument);
            assert_eq!(path.as_slice(), regular_path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected directory-read error, got {other:?}"),
    }
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}
