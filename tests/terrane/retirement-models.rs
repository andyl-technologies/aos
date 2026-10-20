//! Consumes 34 independent retirement record fixtures through public pure codecs.
//!
//! The reference generator prepares Markdown input before compilation. Each
//! positive compares primitive bytes, an independently constructed public model,
//! and every decoded field. Negative wires bypass the rejecting record encoder.
//! The child modules separate wire construction from typed models. These inert
//! values establish no ownership, signature, policy, completed wait or permission.
//!
//! ```text
//! prepared reference -> exact bytes <- primitive wire fields
//!                              |
//!                         owning decoder
//!                              |
//!                      complete public model
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bounded reference fixtures and complete test models must match"
)]

#[path = "retirement_models/models.rs"]
mod models;
#[path = "retirement_models/wire.rs"]
mod wire;

use terrane_format::bucket::{BucketCapabilities, GenerationManifest, Tombstone};
use terrane_format::gc::retirement::*;
use wire::Value::{Array, UInt};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/terrane/retirement-reference.md"
));

fn reference(name: &str) -> Vec<u8> {
    let heading = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&heading).count(), 1, "{name}");
    let section = REFERENCE.split_once(&heading).unwrap().1;
    let section = section.split("\n### ").next().unwrap();
    let hex = section
        .split_once("```hex\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = hex
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(
        digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name}"
    );
    assert_eq!(digits.len() % 2, 0, "{name}");

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

// Each fixture exercises deterministic re-encoding and bounded canonical
// rejection in addition to the independent bytes/model comparisons (TEST-3).
macro_rules! positive {
    ($name:expr, $wire:expr, $model:expr, $record:ty) => {{
        let name = $name;
        let primitive = $wire.encode();
        let expected = $model;
        let published = reference(name);
        assert_eq!(primitive, published, "independent wire: {name}");
        assert_eq!(
            expected.encode().unwrap(),
            published,
            "owning encode: {name}"
        );
        let decoded = <$record>::decode(&published).unwrap();
        assert_eq!(decoded, expected, "complete decoded model: {name}");
        assert_eq!(
            decoded.encode().unwrap(),
            published,
            "canonical re-encoding: {name}"
        );

        for cut in 0..published.len() {
            assert!(
                <$record>::decode(&published[..cut]).is_err(),
                "truncation {name}: {cut}"
            );
        }
        let mut trailing = published.clone();
        trailing.push(0);
        assert!(
            <$record>::decode(&trailing).is_err(),
            "trailing value: {name}"
        );

        // All fixture lengths fit the immediate header; using an additional
        // width for that same length must be refused as noncanonical CBOR.
        assert!(published[0] & 31 < 24);
        let mut noncanonical = vec![(published[0] & 0xe0) | 24, published[0] & 31];
        noncanonical.extend(&published[1..]);
        assert!(
            <$record>::decode(&noncanonical).is_err(),
            "nonminimal header: {name}"
        );
        decoded
    }};
}

fn check_tombstone(bytes: &[u8]) {
    assert_eq!(Tombstone::decode(bytes).unwrap(), models::tombstone());
    assert_eq!(models::tombstone().encode(), wire::tombstone().encode());
}

#[test]
fn reference_retirement_authorization_models_preserve_alternative_fields() {
    let sweep = positive!(
        "retirement-sweep",
        wire::authorization(false, false, false),
        models::sweep(),
        RemoteSweepDeleteAuthorization
    );
    check_tombstone(&sweep.tombstone);
    let (header, records) =
        terrane_format::pack_format::decode_detached_index(&sweep.witness).unwrap();
    assert_eq!(
        header,
        terrane_format::pack_format::Header::new([0x12; 16], false, false)
    );
    assert_eq!(records, Vec::<terrane_format::pack_format::Record>::new());
    assert_eq!(
        PermanentDeleteAuthorization::decode(&reference("retirement-sweep")).unwrap(),
        PermanentDeleteAuthorization::Sweep(models::sweep())
    );
    assert_eq!(
        PermanentDeleteAuthorization::Sweep(models::sweep())
            .encode()
            .unwrap(),
        reference("retirement-sweep")
    );
    assert!(CopiedRetirementAuthorization::decode(&reference("retirement-sweep")).is_err());

    for (local, label) in [(false, "remote"), (true, "local")] {
        for lineage in [false, true] {
            let name = format!(
                "retirement-copy-{label}{}",
                if lineage { "-lineage" } else { "" }
            );
            let copied = positive!(
                &name,
                wire::authorization(true, local, lineage),
                models::copied(local, lineage),
                CopiedRetirementAuthorization
            );
            check_tombstone(&copied.tombstone);
            if let BarrierArtifact::Local(barrier) = &copied.barrier {
                check_tombstone(&barrier.tombstone);
            }
            let model = PermanentDeleteAuthorization::Copied(models::copied(local, lineage));
            assert_eq!(
                PermanentDeleteAuthorization::decode(&reference(&name)).unwrap(),
                model
            );
            assert_eq!(model.encode().unwrap(), reference(&name));
            assert!(RemoteSweepDeleteAuthorization::decode(&reference(&name)).is_err());
        }
    }
}

#[test]
fn reference_retirement_preparation_models_preserve_nested_plan_fields() {
    for (local, label) in [(false, "remote"), (true, "local")] {
        let name = format!("retirement-plan-{label}");
        let plan = positive!(
            &name,
            wire::plan(local),
            models::plan(local),
            CopiedRetirementPlan
        );
        check_tombstone(&plan.tombstone);

        for (phase, revision, discriminant, label_phase) in [
            (PreparationPhase::Preparing, 0, 3, "preparing"),
            (PreparationPhase::Abandoned, 1, 4, "abandoned"),
        ] {
            let name = format!("retirement-preparation-{label}-{label_phase}");
            let primitive = Array(vec![
                UInt(2),
                UInt(revision),
                UInt(discriminant),
                wire::plan(local),
            ]);
            let model = CopiedRetirementPreparation {
                revision,
                phase,
                plan: models::plan(local),
            };
            let preparation = positive!(&name, primitive, model, CopiedRetirementPreparation);
            check_tombstone(&preparation.plan.tombstone);
        }
    }
}

#[test]
fn reference_retirement_operation_models_preserve_phase_and_pointer_fields() {
    for (phase, discriminant, label) in [
        (OperationPhase::Proposed, 0, "proposed"),
        (OperationPhase::Cancelled, 2, "cancelled"),
    ] {
        let name = format!("retirement-operation-{label}");
        positive!(
            &name,
            wire::operation(discriminant, false, false),
            models::operation(phase, false, false),
            PermanentDeleteOperation
        );
    }
    for (copied, local, label) in [
        (false, false, "sweep"),
        (true, false, "remote"),
        (true, true, "local"),
    ] {
        let name = format!("retirement-operation-owned-{label}");
        positive!(
            &name,
            wire::operation(1, copied, local),
            models::operation(OperationPhase::Owned, copied, local),
            PermanentDeleteOperation
        );
    }
}

#[test]
fn reference_retirement_pass_models_preserve_complete_observation_fields() {
    for (local, label) in [(false, "remote"), (true, "local")] {
        for (completed, phase) in [(false, "open"), (true, "completed")] {
            let name = format!("retirement-pass-{label}-{phase}");
            positive!(
                &name,
                wire::progress(local, completed, local),
                models::progress(local, completed, local),
                PermanentDeletePass
            );
        }
    }
}

fn check_fence_records(capabilities: &[u8], manifest: &[u8], copied: bool) {
    assert_eq!(
        BucketCapabilities::decode(capabilities).unwrap(),
        models::capabilities()
    );
    assert_eq!(
        models::capabilities().encode().unwrap(),
        wire::capabilities().encode()
    );
    assert_eq!(
        GenerationManifest::decode(manifest).unwrap(),
        models::manifest(copied)
    );
    assert_eq!(
        models::manifest(copied).encode().unwrap(),
        wire::manifest(copied).encode()
    );
}

#[test]
fn reference_retirement_fence_models_preserve_nested_record_fields() {
    let current = positive!(
        "retirement-current-fence",
        wire::fence(false, false),
        models::current_fields(false, false),
        CurrentCollectionFence
    );
    check_fence_records(
        &current.capabilities,
        current.manifest.as_ref().unwrap(),
        false,
    );

    for (local, label) in [(false, "remote"), (true, "local")] {
        let name = format!("retirement-copied-fence-{label}");
        let copied = positive!(
            &name,
            wire::fence(true, local),
            models::copied_fence(local),
            CopiedPlacementFence
        );
        check_fence_records(&copied.capabilities, &copied.manifest, true);
    }
}

#[test]
fn reference_retirement_owner_models_preserve_disjoint_selection_fields() {
    for (permanent, label) in [(false, "copy"), (true, "permanent")] {
        let name = format!("retirement-selection-{label}");
        positive!(
            &name,
            wire::selection(permanent, [7; 32]),
            models::selection(permanent, [7; 32]),
            PermanentOwnerSelection
        );

        let name = format!("retirement-owner-{label}");
        let primitive = Array(vec![
            wire::bytes([0x12; 16]),
            wire::selection(permanent, [7; 32]),
        ]);
        let model = PermanentBurnOwner {
            pack: [0x12; 16],
            selection: models::selection(permanent, [7; 32]),
        };
        positive!(&name, primitive, model, PermanentBurnOwner);
    }
}

#[test]
fn reference_negative_retirement_wires_require_structural_rejection() {
    let mut missing_witness = wire::authorization(false, false, false);
    missing_witness.remove(7);
    let mut extra_witness = wire::authorization(true, false, false);
    extra_witness.set(7, wire::bytes([]));
    let mut wrong_version = wire::plan(true);
    wrong_version.set(0, UInt(1));
    let mut reserved_phase = wire::operation(0, false, false);
    let Array(fields) = &mut reserved_phase else {
        panic!("operation must be an array")
    };
    fields[2] = UInt(3);
    let mut long_pack = vec![0x12; 16];
    long_pack.push(0);
    let long_owner = Array(vec![wire::bytes(long_pack), Array(vec![UInt(0)])]);
    let mut reversed_coverage = wire::progress(false, false, false);
    reversed_coverage.set(
        11,
        Array(vec![
            Array(vec![UInt(2), UInt(0)]),
            Array(vec![UInt(1), UInt(0)]),
            Array(vec![UInt(0), UInt(0)]),
        ]),
    );
    let mut missing_placement = wire::progress(true, false, true);
    missing_placement.remove(13);

    macro_rules! negative {
        ($name:literal, $primitive:expr, $record:ty, $error:pat) => {{
            let bytes = $primitive.encode();
            assert_eq!(bytes, reference($name), "independent negative: {}", $name);
            assert!(
                matches!(<$record>::decode(&bytes), Err($error)),
                "structural rejection: {}",
                $name
            );
        }};
    }
    negative!(
        "retirement-sweep-missing-witness",
        missing_witness,
        PermanentDeleteAuthorization,
        RetirementError::Schema
    );
    negative!(
        "retirement-copy-extra-witness",
        extra_witness,
        PermanentDeleteAuthorization,
        RetirementError::Schema
    );
    negative!(
        "retirement-plan-wrong-version",
        wrong_version,
        CopiedRetirementPlan,
        RetirementError::Schema
    );
    negative!(
        "retirement-operation-reserved-phase",
        reserved_phase,
        PermanentDeleteOperation,
        RetirementError::Schema
    );
    negative!(
        "retirement-owner-long-pack",
        long_owner,
        PermanentBurnOwner,
        RetirementError::Cbor(terrane_format::cbor::Error::Limit)
    );
    negative!(
        "retirement-pass-reversed-coverage",
        reversed_coverage,
        PermanentDeletePass,
        RetirementError::Schema
    );
    negative!(
        "retirement-local-pass-missing-placement",
        missing_placement,
        PermanentDeletePass,
        RetirementError::Contradiction
    );

    // The byte cap is checked before the decoder interprets or allocates a
    // represented record. No operational allocation or effect is involved.
    let oversized = vec![0; MAX_RECORD_BYTES + 1];
    macro_rules! byte_cap {
        ($record:ty) => {
            assert_eq!(
                <$record>::decode(&oversized),
                Err(RetirementError::Cbor(terrane_format::cbor::Error::Limit)),
                "record byte cap: {}",
                stringify!($record)
            );
        };
    }
    byte_cap!(PermanentDeleteAuthorization);
    byte_cap!(RemoteSweepDeleteAuthorization);
    byte_cap!(CopiedRetirementAuthorization);
    byte_cap!(CopiedRetirementPlan);
    byte_cap!(CopiedRetirementPreparation);
    byte_cap!(PermanentDeleteOperation);
    byte_cap!(PermanentDeletePass);
    byte_cap!(PermanentOwnerSelection);
    byte_cap!(PermanentBurnOwner);
    byte_cap!(CurrentCollectionFence);
    byte_cap!(CopiedPlacementFence);
}
