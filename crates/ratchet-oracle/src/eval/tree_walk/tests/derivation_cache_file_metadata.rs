//! Derivation force-cache surface tests for filesystem metadata inputs.

use super::derivation_cache_support::*;
use super::*;

#[test]
fn persistent_read_dir_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-dir-drv-source");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("alpha"), b"data").expect("alpha writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-dir-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readDir ./dir).alpha ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
        )
        .expect("fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-read-dir-drv-surface-parity",
        &ir,
        source,
        expected_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_dir_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-dir-drv-stale-source");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let first_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"target", FileTypeForInput::Regular)],
        )
        .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"target", FileTypeForInput::Directory)],
        )
        .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-dir-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readDir ./dir).target ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-read-dir-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::remove_file(root.join("dir").join("target")).expect("target file removes");
            fs::create_dir(root.join("dir").join("target")).expect("target directory creates");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_file_type_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-type-drv-source");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-type-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFileType ./target) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-read-file-type-drv-surface-parity",
        &ir,
        source,
        expected_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_file_type_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-type-drv-stale-source");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let first_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Directory)
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-type-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFileType ./target) ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-read-file-type-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::remove_file(root.join("target")).expect("target file removes");
            fs::create_dir(root.join("target")).expect("target directory creates");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}
