//! Tests for batched, memoized store metadata.

use super::{
    PathRecord, StoreQueries, closure_of, merge_rewrites, nix32_nar_hash,
    parse_validity_registrations, partition_by_shared_closure, require_rewrite_per_root,
    run_concurrently,
};
use std::collections::HashMap;

const ROOT: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-1.0";
const LIB: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-lib-2.0";
const LIBC: &str = "/nix/store/cccccccccccccccccccccccccccccccc-libc-3.0";
const OTHER: &str = "/nix/store/dddddddddddddddddddddddddddddddd-other-4.0";
const DATA: &str = "/nix/store/ffffffffffffffffffffffffffffffff-data-5.0";

/// A real `nix-store --dump-db` digest and its `nix-store --query --hash` form.
const BASE16_HASH: &str = "85ec42838f2527e9c2ee76de9d3b8a02790a40722bd34f471c0016bc2f98f824";
const NIX32_HASH: &str = "sha256:097qk0pvq5h03i3lzlrbf900ly82i8xrvpknxv1fj9r5iy1l5v45";

fn record(nar_size: u64, references: &[&str]) -> PathRecord {
    PathRecord {
        nar_hash: format!("sha256:{nar_size:052}"),
        nar_size,
        deriver: None,
        references: references.iter().map(|path| (*path).to_string()).collect(),
    }
}

/// ROOT -> {ROOT, LIB}, LIB -> {LIBC}, OTHER -> {LIBC}, DATA -> {}.
fn records() -> HashMap<String, PathRecord> {
    HashMap::from([
        (ROOT.to_string(), record(10, &[LIB, ROOT])),
        (LIB.to_string(), record(20, &[LIBC])),
        (LIBC.to_string(), record(400, &[LIBC])),
        (OTHER.to_string(), record(30, &[LIBC])),
        (DATA.to_string(), record(5, &[])),
    ])
}

fn hash(path: &str) -> String {
    super::extract_hash(path).to_string()
}

#[test]
fn nar_hash_matches_nix_store_query_form() {
    assert_eq!(nix32_nar_hash(BASE16_HASH).unwrap(), NIX32_HASH);
}

#[test]
fn nar_hash_rejects_non_sha256_digests() {
    assert!(nix32_nar_hash("").is_err());
    assert!(nix32_nar_hash(&BASE16_HASH[1..]).is_err());
    assert!(nix32_nar_hash(&BASE16_HASH.replace('8', "g")).is_err());
}

#[test]
fn validity_registrations_parse_derivers_and_references() {
    let text = format!(
        "{ROOT}\n{BASE16_HASH}\n12477152\n/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root-1.0.drv\n\
         2\n{LIB}\n{ROOT}\n{LIB}\n{BASE16_HASH}\n7\n\n0\n"
    );

    let records = parse_validity_registrations(&text).unwrap();

    assert_eq!(records.len(), 2);
    let (root_path, root) = &records[0];
    assert_eq!(root_path, ROOT);
    assert_eq!(root.nar_hash, NIX32_HASH);
    assert_eq!(root.nar_size, 12_477_152);
    assert_eq!(
        root.deriver.as_deref(),
        Some("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root-1.0.drv")
    );
    assert_eq!(root.references, [LIB, ROOT]);

    let (lib_path, lib) = &records[1];
    assert_eq!(lib_path, LIB);
    assert_eq!(lib.deriver, None);
    assert!(lib.references.is_empty());
}

#[test]
fn validity_registrations_reject_truncated_or_malformed_records() {
    let truncated = format!("{ROOT}\n{BASE16_HASH}\n7\n\n2\n{LIB}\n");
    let bad_size = format!("{ROOT}\n{BASE16_HASH}\nseven\n\n0\n");
    let bad_count = format!("{ROOT}\n{BASE16_HASH}\n7\n\nmany\n");
    let empty_path = format!("\n{BASE16_HASH}\n7\n\n0\n");

    for text in [truncated, bad_size, bad_count, empty_path] {
        assert!(parse_validity_registrations(&text).is_err(), "{text:?}");
    }
}

#[test]
fn closure_is_sorted_and_complete() {
    let records = records();

    let closure = closure_of(&records, ROOT).unwrap();

    assert_eq!(closure.into_iter().collect::<Vec<_>>(), [ROOT, LIB, LIBC]);
}

#[test]
fn closure_refuses_unloaded_references() {
    let mut records = records();
    records.remove(LIBC);

    let error = closure_of(&records, ROOT).unwrap_err();

    assert!(format!("{error:#}").contains("references unloaded path"));
}

#[test]
fn introspection_matches_individual_store_queries() {
    let store = StoreQueries::from_parts(records(), HashMap::new());

    let info = store.introspect(ROOT).unwrap();

    assert_eq!(info.path, ROOT);
    assert_eq!(info.nar_size, 10);
    // `--references` without the self-reference, as hashes.
    assert_eq!(info.references, [hash(LIB)]);
    // NAR sizes of ROOT, LIB, and LIBC.
    assert_eq!(info.closure_size, 430);
}

#[test]
fn closure_edges_and_nars_cover_each_member_once() {
    let store = StoreQueries::from_parts(records(), HashMap::new());

    let edges = store.closure_edges(ROOT).unwrap();
    let nars = store.closure_nars(ROOT).unwrap();

    assert_eq!(
        edges,
        [
            (hash(ROOT), vec![hash(LIB)]),
            (hash(LIB), vec![hash(LIBC)]),
            (hash(LIBC), Vec::new()),
        ]
    );
    assert_eq!(
        nars.iter()
            .map(|member| (member.path.as_str(), member.nar_size))
            .collect::<Vec<_>>(),
        [(ROOT, 10), (LIB, 20), (LIBC, 400)]
    );
}

#[test]
fn remembered_content_addresses_report_only_the_root() {
    // A batch remembers each requested root's rewrite, as Nix reports it.
    let rewrites = [ROOT, OTHER]
        .into_iter()
        .map(|path| (hash(path), format!("ca-{}", hash(path))))
        .collect::<HashMap<_, _>>();
    let store = StoreQueries::from_parts(records(), rewrites);

    let addresses = store.content_addresses(ROOT).unwrap();

    assert_eq!(
        addresses,
        HashMap::from([(hash(ROOT), format!("ca-{}", hash(ROOT)))])
    );
}

#[test]
fn batch_rewrites_must_match_the_requested_roots() {
    let rewrite = |path: &str| (hash(path), format!("ca-{}", hash(path)));
    let exact = HashMap::from([rewrite(ROOT), rewrite(OTHER)]);
    let missing = HashMap::from([rewrite(ROOT)]);
    let closure_member = HashMap::from([rewrite(ROOT), rewrite(LIB)]);
    let extra = HashMap::from([rewrite(ROOT), rewrite(OTHER), rewrite(LIB)]);

    require_rewrite_per_root(&[ROOT, OTHER], &exact).unwrap();
    for rewrites in [missing, closure_member, extra] {
        assert!(require_rewrite_per_root(&[ROOT, OTHER], &rewrites).is_err());
    }
}

#[test]
fn rewrites_merge_only_when_consistent() {
    let mut known = HashMap::from([(hash(LIB), "ca-lib".to_string())]);

    merge_rewrites(
        &mut known,
        HashMap::from([
            (hash(LIB), "ca-lib".to_string()),
            (hash(LIBC), "ca-libc".to_string()),
        ]),
    )
    .unwrap();
    assert_eq!(known.len(), 2);

    let conflict = HashMap::from([(hash(LIB), "ca-other".to_string())]);
    assert!(merge_rewrites(&mut known, conflict).is_err());
}

#[test]
fn partition_keeps_shared_closures_together() {
    let mut records = records();
    records.insert(DATA.to_string(), record(500, &[]));

    // ROOT and OTHER share the heavy LIBC, so the second costs its group only
    // 30 more bytes; DATA is heavier and shares nothing.
    let groups = partition_by_shared_closure(&records, &[OTHER, ROOT, DATA], 2).unwrap();

    assert_eq!(groups, [vec![DATA], vec![ROOT, OTHER]]);
}

#[test]
fn partition_spreads_disjoint_work_across_groups() {
    let records = records();

    // Sharing LIBC would make one 460-byte group; two 430-byte groups finish
    // sooner, and the small DATA closure joins the earlier one.
    let groups = partition_by_shared_closure(&records, &[DATA, OTHER, ROOT], 2).unwrap();

    assert_eq!(groups, [vec![ROOT, DATA], vec![OTHER]]);
}

#[test]
fn partition_is_bounded_and_covers_every_root() {
    let records = records();
    let roots = [ROOT, LIB, LIBC, OTHER, DATA];

    for workers in [1, 2, 3, 16] {
        let groups = partition_by_shared_closure(&records, &roots, workers).unwrap();

        assert!(groups.len() <= workers);
        let mut assigned = groups.concat();
        assigned.sort_unstable();
        let mut expected = roots.to_vec();
        expected.sort_unstable();
        assert_eq!(assigned, expected);
    }
}

#[test]
fn concurrent_results_keep_input_order() {
    let items = (0..200_u64).collect::<Vec<_>>();

    let results = run_concurrently(&items, |item| {
        // Finish later items first to expose any completion-order leak.
        std::thread::sleep(std::time::Duration::from_micros(200 - item));
        item * 2
    });

    assert_eq!(
        results,
        items.iter().map(|item| item * 2).collect::<Vec<_>>()
    );
}

#[test]
fn references_follow_nix_store_topological_order() {
    // ROOT references A, B, C, and itself; B depends on A and C depends on B.
    // Path order alone would print C, B, A; Nix prints dependencies first.
    const A: &str = "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-a";
    const B: &str = "/nix/store/gggggggggggggggggggggggggggggggg-b";
    const C: &str = "/nix/store/00000000000000000000000000000000-c";
    let records = HashMap::from([
        (ROOT.to_string(), record(1, &[C, B, A, ROOT])),
        (A.to_string(), record(1, &[])),
        (B.to_string(), record(1, &[A, B])),
        (C.to_string(), record(1, &[B, DATA])),
        (DATA.to_string(), record(1, &[])),
    ]);
    let store = StoreQueries::from_parts(records, HashMap::new());

    let info = store.introspect(ROOT).unwrap();

    assert_eq!(info.references, [hash(A), hash(B), hash(C)]);
}
