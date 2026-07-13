//! Mechanical coverage for the relocation-sensitive payload-identity audit.
//!
//! The table below is the executable counterpart of RFC-0007 doc 30 section
//! 2.4. Direct raw-payload readers are representation-only, address-identity
//! readers are confined to helpers with no collector safepoint, and every key
//! or reference that can survive a moving collection is named in the B2 repair
//! worklist. Adding or reclassifying an accessor requires updating this table.
//!
//! The Candidate-C FV-0 reclassification routed the inline scalar-decode
//! `payload_bits` readers in `eval_codec`, `eval_list_map`, `eval_raw`,
//! `eval_source`, `eval_trace`, `serialize_xml`, and two of the three in
//! `eval_compare` through the heap scalar-decode seam, so those consumers no
//! longer read raw payload bits (raw-representation total 29 -> 11). The
//! Candidate-C carrier's own accessor definitions live in
//! `value/candidate_c_carrier.rs`, excluded here alongside `value.rs`.
//!
//! The S4b tier-1 JIT value-word facade then folded the two `lower.rs`
//! constant-embedding relocation readers into one `lower/value_words.rs`
//! `embedded_constant_words` reader (relocation-sensitive total 20 -> 19), and
//! dropped the two `lower/candidate_c.rs` raw `payload_bits` constant readers —
//! the one-word carrier now decodes embeddable constants through the typed
//! `as_int`/`as_bool` accessors, which reject arena-backed words, so no raw read
//! remains (raw-representation total 11 -> 9).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// Deliberately omit the leading `.` so UFCS calls such as
// `Value::payload_bits(value)` are counted too.
const RAW_ACCESSOR: &str = "payload_bits(";
const ADDRESS_ONLY_ACCESSOR: &str = "address_identity_bits(";
const TRANSIENT_IDENTITY_ACCESSOR: &str = "transient_identity_bits(";
const RELOCATION_SENSITIVE_ACCESSOR: &str = "relocation_sensitive_identity_bits(";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PayloadIdentityAuditRow {
    path: &'static str,
    raw_representation: usize,
    address_identity_only: usize,
    relocation_sensitive: usize,
    b2_disposition: &'static str,
}

const PAYLOAD_IDENTITY_AUDIT: &[PayloadIdentityAuditRow] = &[
    PayloadIdentityAuditRow {
        // The tier-1 constant-embedding read moved here from `lower.rs` when the
        // width-generic value-word facade landed (S4b): the two former call sites
        // consolidated into one `embedded_constant_words` reader on the baseline
        // carrier. The `candidate_c.rs` raw `payload_bits` readers were dropped in
        // the same refactor — the one-word carrier decodes constants through the
        // typed `as_int`/`as_bool` accessors, which reject arena-backed words,
        // rather than reading raw payload bits.
        path: "ratchet-jit/src/lower/value_words.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 1,
        b2_disposition: "reject heap constants before CLIF payload emission",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-jit/src/lower/alloc_cons.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 1,
        b2_disposition: "reject heap constants before singleton-list head emission",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/env.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 2,
        b2_disposition: "rewrite active, suspended, and captured AtomicValueCell roots",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/heap/arena.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 2,
        b2_disposition: "rebuild container structural hashes and hash-cons buckets",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/heap/roots.rs",
        raw_representation: 2,
        address_identity_only: 0,
        relocation_sensitive: 0,
        b2_disposition: "diagnostic mismatch payloads only; no repair",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/alloc_intern.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 1,
        b2_disposition: "derive removal keys from the relocated active force root",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/capture_validation.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 2,
        b2_disposition: "rekey test-only capture validation state or pin collection off",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_compare.rs",
        raw_representation: 1,
        address_identity_only: 0,
        relocation_sensitive: 0,
        b2_disposition: "inline scalar decoding only; no repair",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_core.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 6,
        b2_disposition: "rekey thunk sets and derive active-force removals after root relocation",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_core/force_identity.rs",
        raw_representation: 0,
        address_identity_only: 3,
        relocation_sensitive: 0,
        b2_disposition: "collector-free recursive hash walk; no repair",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_core/force_payload.rs",
        raw_representation: 0,
        address_identity_only: 2,
        relocation_sensitive: 0,
        b2_disposition: "collector-free payload walk (cycle seen-set); plus the observe \
                         payload-memo key, retained only within one run and dropped at the \
                         run boundary. Under B2 the memo must invalidate on every moving \
                         safepoint or rekey; see force_payload_memo.",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_core/memo.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 1,
        b2_disposition: "clear the advisory unhashable-value set in the live commit",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/eval_numeric.rs",
        raw_representation: 2,
        address_identity_only: 0,
        relocation_sensitive: 0,
        b2_disposition: "inline numeric and boolean decoding only; no repair",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/outcome.rs",
        raw_representation: 4,
        address_identity_only: 0,
        relocation_sensitive: 0,
        b2_disposition: "diagnostic mismatch payloads only; no repair",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-oracle/src/eval/tree_walk/tier1_publish.rs",
        raw_representation: 0,
        address_identity_only: 0,
        relocation_sensitive: 3,
        b2_disposition: "rekey tier-1 publish slots in the live commit after forwarding",
    },
    PayloadIdentityAuditRow {
        path: "ratchet-value/src/attrs/shape/instance.rs",
        raw_representation: 0,
        address_identity_only: 1,
        relocation_sensitive: 0,
        b2_disposition: "transient representation identity in a collector-free fingerprint walk",
    },
];

fn count_accessors(source: &str) -> (usize, usize, usize) {
    (
        source.matches(RAW_ACCESSOR).count(),
        source.matches(ADDRESS_ONLY_ACCESSOR).count()
            + source.matches(TRANSIENT_IDENTITY_ACCESSOR).count(),
        source.matches(RELOCATION_SENSITIVE_ACCESSOR).count(),
    )
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).unwrap_or_else(|error| {
        panic!(
            "payload-identity audit cannot read {}: {error}",
            directory.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("payload-identity audit cannot read a directory entry: {error}")
        });
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && !path.file_name().is_some_and(|name| name == "tests.rs")
        {
            sources.push(path);
        }
    }
}

fn audited_source_counts() -> BTreeMap<String, (usize, usize, usize)> {
    let crates_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ratchet-oracle lives below the crates root");
    let mut sources = Vec::new();
    for crate_name in ["ratchet-jit", "ratchet-oracle", "ratchet-value"] {
        collect_rust_sources(&crates_root.join(crate_name).join("src"), &mut sources);
    }

    // The `Value` carrier's own accessor *definitions* are not consumer call
    // sites: the baseline carrier defines them in `value.rs` and the Candidate-C
    // carrier in `candidate_c_carrier.rs`. Both are excluded so the audit counts
    // only accessor consumers.
    let excluded_value_definitions = [
        crates_root.join("ratchet-value/src/value.rs"),
        crates_root.join("ratchet-value/src/value/candidate_c_carrier.rs"),
    ];
    let mut counts = BTreeMap::new();
    for path in sources {
        if excluded_value_definitions.contains(&path) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "payload-identity audit cannot read {}: {error}",
                path.display()
            )
        });
        let accessor_counts = count_accessors(&source);
        if accessor_counts == (0, 0, 0) {
            continue;
        }
        let relative = path
            .strip_prefix(crates_root)
            .expect("audited source is below the crates root")
            .to_string_lossy()
            .replace('\\', "/");
        counts.insert(relative, accessor_counts);
    }
    counts
}

// This audit scans source text for accessor call sites, so it is carrier-
// independent and runs on both carriers.
#[test]
fn payload_identity_accessors_match_the_reviewed_b2_worklist() {
    let expected = PAYLOAD_IDENTITY_AUDIT
        .iter()
        .map(|row| {
            assert!(
                !row.b2_disposition.is_empty(),
                "{} has no disposition",
                row.path
            );
            (
                row.path.to_owned(),
                (
                    row.raw_representation,
                    row.address_identity_only,
                    row.relocation_sensitive,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let actual = audited_source_counts();

    assert_eq!(actual, expected);
    assert_eq!(
        PAYLOAD_IDENTITY_AUDIT
            .iter()
            .map(|row| row.raw_representation)
            .sum::<usize>(),
        9
    );
    assert_eq!(
        PAYLOAD_IDENTITY_AUDIT
            .iter()
            .map(|row| row.address_identity_only)
            .sum::<usize>(),
        6
    );
    assert_eq!(
        PAYLOAD_IDENTITY_AUDIT
            .iter()
            .map(|row| row.relocation_sensitive)
            .sum::<usize>(),
        19
    );
    let production_rows = PAYLOAD_IDENTITY_AUDIT
        .iter()
        .filter(|row| !row.path.ends_with("capture_validation.rs"));
    assert_eq!(production_rows.clone().count(), 15);
    assert_eq!(
        production_rows
            .map(|row| {
                (
                    row.raw_representation,
                    row.address_identity_only,
                    row.relocation_sensitive,
                )
            })
            .fold((0, 0, 0), |left, right| {
                (left.0 + right.0, left.1 + right.1, left.2 + right.2)
            }),
        (9, 6, 17)
    );
}
