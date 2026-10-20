//! Public ref, snapshot and reflog models with independently assembled fields.
//!
//! Candidate IDs are inert selectors. Retained predecessor claims are compared
//! as data and never treated as proof that a backend selected a candidate.

use super::{
    commits, fields,
    support::{Value, a, encode, m, n, set, t},
};
use terrane_format::refs::{
    Locality, MergePolicy, RefLogReason, RefLogRecord, RefName, RefPolicy, RefRecord, Retention,
    SnapshotEnvelope,
};

/// Constructs a complete public ref value with an optional opaque selector.
pub(crate) fn record(seq: u8, selected: bool) -> RefRecord {
    RefRecord {
        commit: [seq; 32],
        seq: u64::from(seq),
        writer_epoch: 7,
        home: commits::locality(),
        policy: None,
        candidate_id: selected.then_some([15; 32]),
    }
}

/// Builds a complete inert annotation through public data models.
///
/// # Panics
/// Panics if the fixed canonical tag is rejected or the independent envelope
/// table violates its invariant of being a map containing attestation field 3.
fn envelope() -> SnapshotEnvelope {
    let tag = RefName::parse("refs/tags/_/snapshot")
        .unwrap_or_else(|error| panic!("tag fixture: {error}"));
    let mut primitive = fields::envelope();
    // The public attestation field is raw CBOR. Its independent primitive
    // submodel is shared with the wire witness, without decoding that wire.
    let Value::Map(ref mut fields) = primitive else {
        unreachable!("envelope table is a map")
    };
    let attestation = fields
        .iter()
        .find_map(|(key, value)| matches!(key, Value::UInt(3)).then_some(value))
        .unwrap_or_else(|| panic!("missing attestation table"));
    SnapshotEnvelope {
        tag,
        commit: [1; 32],
        attestation: encode(attestation),
        signer_key: "cd".repeat(32),
        signature: [14; 64],
    }
}

/// Constructs public ref policy and annotation alternatives alongside independent field tables.
///
/// # Panics
/// Panics if the fixed tag is rejected, the attestation table is missing, or
/// an independent table no longer supports its required field paths.
pub(crate) fn refs() -> Vec<(String, RefRecord, Value)> {
    let mut models = vec![
        (
            "ref-legacy".into(),
            record(1, false),
            fields::record(1, false),
        ),
        (
            "ref-selected".into(),
            record(1, true),
            fields::record(1, true),
        ),
    ];
    let mut model = record(1, true);
    model.policy = Some(RefPolicy::default());
    let mut primitive = fields::record(1, true);
    set(&mut primitive, &[5], m(vec![]));
    models.push(("ref-empty-policy".into(), model, primitive));
    let retentions = [
        Retention::Gc,
        Retention::Lease,
        Retention::Forever,
        Retention::Ttl(99),
    ];
    for (index, retention) in retentions.into_iter().enumerate() {
        let selected = index % 2 == 1;
        let mut model = record(1, selected);
        model.policy = Some(RefPolicy {
            multi_writer: Some(selected),
            merge_policies: Some(vec![
                MergePolicy::PreferOurs,
                MergePolicy::PreferTheirs,
                MergePolicy::PreferTrusted,
                MergePolicy::PreferNewer,
                MergePolicy::KeepConflict,
                MergePolicy::Error,
            ]),
            retention: Some(retention),
            conflicted: Some(!selected),
            snapshot: Some(envelope()),
        });
        let retention_field = match index {
            0 => t("gc"),
            1 => t("lease"),
            2 => t("forever"),
            _ => a(vec![t("ttl"), n(99)]),
        };
        let mut primitive = fields::record(1, selected);
        set(
            &mut primitive,
            &[5],
            m(vec![
                (1, Value::Bool(selected)),
                (2, a(fields::POLICIES.into_iter().map(t).collect())),
                (3, retention_field),
                (4, Value::Bool(!selected)),
                (5, fields::envelope()),
            ]),
        );
        models.push((format!("ref-policy-{index}"), model, primitive));
    }
    let mut model = record(1, false);
    model.home = Locality::default();
    let mut primitive = fields::record(1, false);
    set(&mut primitive, &[4], m(vec![]));
    models.push(("ref-empty-locality".into(), model, primitive));
    models
}

fn log(reason: RefLogReason, mode: &str) -> RefLogRecord {
    let mut model = RefLogRecord {
        record: record(2, mode != "legacy"),
        previous_commit: Some([1; 32]),
        principal: "subject".into(),
        reason,
        timestamp: 24,
        expected_previous: None,
        committed_previous: None,
    };
    match mode {
        "fresh" => {
            model.record = record(1, true);
            model.previous_commit = None;
            model.expected_previous = Some(None);
        }
        "expected" => model.expected_previous = Some(Some(record(1, true))),
        "retained" => {
            model.expected_previous = Some(None);
            model.committed_previous = Some(record(1, true));
        }
        _ => {}
    }
    model
}

/// Constructs public reflogs preserving CAS expectations and retained predecessors as data.
///
/// # Panics
/// Panics if an independent table no longer supports its required field paths.
pub(crate) fn logs() -> Vec<(String, RefLogRecord, Value)> {
    let reasons = [
        RefLogReason::Commit,
        RefLogReason::Merge,
        RefLogReason::Fold,
        RefLogReason::Rollback,
        RefLogReason::JobCheckpoint,
        RefLogReason::Migrate,
    ];
    let mut models: Vec<_> = reasons
        .into_iter()
        .zip(fields::REASONS)
        .map(|(reason, name)| {
            (
                format!("log-legacy-{name}"),
                log(reason, "legacy"),
                fields::log(name, "legacy"),
            )
        })
        .collect();
    for mode in ["fresh", "expected", "retained"] {
        models.push((
            format!("log-selected-{mode}"),
            log(RefLogReason::Commit, mode),
            fields::log("commit", mode),
        ));
    }
    let mut model = log(RefLogReason::Migrate, "expected");
    model.record.home = Locality {
        region: Some("destination".into()),
        zone: None,
        host: None,
    };
    model.record.policy = Some(RefPolicy {
        retention: Some(Retention::Forever),
        ..RefPolicy::default()
    });
    if let Some(Some(previous)) = &mut model.expected_previous {
        previous.policy = Some(RefPolicy {
            retention: Some(Retention::Gc),
            ..RefPolicy::default()
        });
    }
    let mut primitive = fields::log("migrate", "expected");
    set(&mut primitive, &[1, 4], m(vec![(1, t("destination"))]));
    set(&mut primitive, &[1, 5], m(vec![(3, t("forever"))]));
    set(&mut primitive, &[6, 5], m(vec![(3, t("gc"))]));
    models.push(("log-migrate-locality-policy".into(), model, primitive));
    models
}
