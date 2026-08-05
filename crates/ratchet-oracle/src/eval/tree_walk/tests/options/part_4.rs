//! Split-out tests (part_4). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_reflected_context_outputs_list_preserves_accumulated_outputs() {
    let ir = lower("\"root\"");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let mut group =
        ReflectedContextGroup::new(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv".to_vec());
    group.outputs = vec![b"out".to_vec(), b"dev".to_vec()];
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_reflected_context_group(ir.root, span, group)
        })
        .expect("reflected context group allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "reflected context outputs list did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating reflected context outputs list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let outputs_key = evaluator
        .symbols
        .intern(b"outputs")
        .expect("outputs key interns");
    let outputs = {
        let group_attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("context group is an attrset");
        assert_eq!(group_attrs.len(), 1);
        group_attrs.get(outputs_key).expect("outputs attr exists")
    };
    let output_items = {
        let outputs = evaluator
            .heap()
            .get_list(outputs)
            .expect("outputs value is a heap-owned list");
        assert_eq!(outputs.len(), 2);
        [
            outputs.get(0).expect("first output exists"),
            outputs.get(1).expect("second output exists"),
        ]
    };
    assert_heap_string_bytes(&evaluator, output_items[0], b"out");
    assert_heap_string_bytes(&evaluator, output_items[1], b"dev");
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocList,
        ],
        "reflected context should dispatch output-name strings and the outputs list but not the final generated attrset"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 4,
        "reflected context should allocate exactly two output strings, the outputs list, and the final attrset under GC stress"
    );
    let final_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("reflected context final attrset allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_substring_string_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(r#"builtins.substring 1 2 "abcd""#, b"bc");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_add_operator_scalar_results_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(r#""a" + "b""#, b"ab");
    assert_gc_stress_root_path_result_dispatches(
        r#"/tmp/gc-stress-root + "/name""#,
        b"/tmp/gc-stress-root/name",
        None,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_to_string_scalar_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches("builtins.toString 123", b"123");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_store_path_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(
        r#"builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src""#,
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_to_file_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(
        r#"builtins.toFile "foo" "bar""#,
        b"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_to_file_result_skips_unregistered_outer_locals() {
    assert_gc_stress_root_bool_result_skips_dispatch(
        r#""left" == builtins.toFile "foo" "bar""#,
        false,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_interpolation_literal_result_dispatch_permanent_noop_bridge() {
    let root = IrId::new(0);
    let span = Span::new(0, 2);
    let ir = manual_ir(root, vec![pure_node(IrKind::Interp, span, IrData::None)]);
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress interpolation expression evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while evaluating manual empty interpolation"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .get_string(value)
            .expect("interpolation result is heap-owned")
            .bytes(),
        b""
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root interpolation allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_path_interpolation_coercion_skips_unregistered_outer_locals() {
    let (dir, path) = temp_file_with_bytes("gc-stress-path-interpolation", b"abc");
    let path = path_source(&path);
    assert_gc_stress_root_bool_result_skips_dispatch(&format!(r#""left" == "${{{path}}}""#), false);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_path_source_string_results_skip_interned_source_setup() {
    let (file_dir, file_path) = temp_file_with_bytes("gc-stress-source-path", b"abc");
    let file_path = path_source(&file_path);
    let source = format!("builtins.path {{ path = {file_path}; }}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_skips_dispatch(&source, &expected);
    fs::remove_dir_all(file_dir).expect("temp directory removes");

    let dir = unique_temp_dir("gc-stress-source-path-filter");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    let source = format!("builtins.path {{ path = {tree}; filter = ({keep}); }}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_skips_dispatch(&source, &expected);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_filter_source_string_result_dispatch_permanent_noop_bridge() {
    let dir = unique_temp_dir("gc-stress-filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    let source = format!("builtins.filterSource ({keep}) {tree}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_dispatches(&source, &expected);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_source_path_string_results_skip_unregistered_outer_locals() {
    let (file_dir, file_path) = temp_file_with_bytes("gc-stress-nested-source-path", b"abc");
    let file_path = path_source(&file_path);
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.path {{ path = {file_path}; }}"#),
        false,
    );
    fs::remove_dir_all(file_dir).expect("temp directory removes");

    let dir = unique_temp_dir("gc-stress-nested-filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.filterSource ({keep}) {tree}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetchurl_result_dispatch_permanent_noop_bridge() {
    let (dir, path) = temp_file_with_bytes("gc-stress-fetchurl", b"abc");
    let url = nix_string_literal(&format!("file://{}", path_source(&path)));
    assert_gc_stress_root_string_result_dispatches(
        &format!("builtins.fetchurl {url}"),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt",
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_fetchurl_result_skips_unregistered_outer_locals() {
    let (dir, path) = temp_file_with_bytes("gc-stress-nested-fetchurl", b"abc");
    let url = nix_string_literal(&format!("file://{}", path_source(&path)));
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.fetchurl {url}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_string_result_dispatch_permanent_noop_bridge() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!("builtins.fetchTarball {url}");
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_string_result_dispatches_with_options(&source, &expected, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_fixed_attrset_results_skip_interned_composite_roots() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball-fixed");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-fixed-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_string_result_skips_dispatch_with_options(&source, &expected, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_reused_fixed_attrset_result_skips_interned_composite_roots() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball-reuse");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-reuse-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_eq!(
        eval_string_bytes_with_options(&source, options.clone()),
        expected
    );
    fs::remove_dir_all(&archive_dir).expect("archive temp directory removes");

    assert_gc_stress_root_string_result_skips_dispatch_with_options(&source, &expected, options);

    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_fetch_tarball_result_skips_unregistered_outer_locals() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-nested-fetch-tarball");
    let store_dir = unique_temp_dir("gc-stress-nested-fetch-tarball-store");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let source = format!(
        r#""left" == builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_bool_result_skips_dispatch_with_options(&source, false, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_result_dispatch_permanent_noop_bridge() {
    let (dir, path) = temp_file_with_bytes("gc-stress-read-file", b"abc");
    let path = nix_string_literal(&path_source(&path));
    assert_gc_stress_root_string_result_dispatches(&format!("builtins.readFile {path}"), b"abc");
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_type_result_dispatch_permanent_noop_bridge() {
    let (dir, regular) = temp_file_with_bytes("gc-stress-read-file-type", b"abc");
    let nested = dir.join("nested");
    fs::create_dir(&nested).expect("nested directory creates");
    let cases = [
        (
            nix_string_literal(&path_source(&regular)),
            b"regular".as_slice(),
        ),
        (
            nix_string_literal(&path_source(&nested)),
            b"directory".as_slice(),
        ),
    ];

    for (path, expected) in cases {
        assert_gc_stress_root_string_result_dispatches(
            &format!("builtins.readFileType {path}"),
            expected,
        );
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_text_store_result_skips_nested_text_store_setup() {
    assert_gc_stress_root_string_result_skips_dispatch(
        r#"builtins.readFile (builtins.toFile "gc-read" "abc")"#,
        b"abc",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_read_file_result_skips_unregistered_outer_locals() {
    assert_gc_stress_root_bool_result_skips_dispatch(
        r#""left" == builtins.readFile (builtins.toFile "gc-read" "abc")"#,
        false,
    );

    let (dir, path) = temp_file_with_bytes("gc-stress-nested-read-file", b"abc");
    let path = nix_string_literal(&path_source(&path));
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.readFile {path}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_dir_empty_attrset_result_skips_primop_composite_dispatch() {
    let dir = unique_temp_dir("gc-stress-read-dir-empty");
    let source = format!(
        "builtins.readDir {}",
        nix_string_literal(&path_source(&dir))
    );
    let ir = lower(&source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress readDir evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated readDir attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("readDir result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("readDir result attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_read_dir_entry_type_strings_dispatch_before_attrset_skip() {
    let dir = unique_temp_dir("gc-stress-read-dir-entry-types");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    let path = path_source(&dir);
    let source = format!("builtins.readDir {}", nix_string_literal(&path));
    let ir = lower(&source);
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("readDir argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let argument_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(path.into_bytes()))
        .expect("argument path string allocates");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, root.span, &mut roots, |eval| {
            eval.eval_read_dir_primop(ir.root, root.span, argument, argument_span, argument_value)
        })
        .expect("GC-stress non-empty readDir evaluates");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while readDir entry type strings allocated"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let regular_key = evaluator
        .symbols
        .intern(b"regular")
        .expect("regular key interns");
    let nested_key = evaluator
        .symbols
        .intern(b"nested")
        .expect("nested key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("readDir result is heap-owned");
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(regular_key).expect("regular attr exists"))
            .expect("regular type string is heap-owned")
            .bytes(),
        b"regular"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(nested_key).expect("nested attr exists"))
            .expect("nested type string is heap-owned")
            .bytes(),
        b"directory"
    );
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count()
            >= permanent_safepoints_before + 3,
        "two entry type strings and final attrset should allocate under GC stress"
    );
    let final_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("readDir final attrset allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_try_eval_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.tryEval 7");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress tryEval evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated tryEval attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let success_key = evaluator
        .symbols
        .intern(b"success")
        .expect("success key interns");
    let value_key = evaluator
        .symbols
        .intern(b"value")
        .expect("value key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("tryEval result is heap-owned");
    assert_eq!(
        attrs
            .get(success_key)
            .expect("success attr exists")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        attrs.get(value_key).expect("value attr exists").as_int(),
        Ok(7)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("tryEval result attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}
