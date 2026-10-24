//! Reconstructs structural negatives with primitive CBOR and bounded raw heads.
//!
//! No malformed input passes through its rejecting owning encoder. Decoder
//! errors demonstrate structural refusal only, without an authority decision.
//!
//! ```text
//! negative_fields -> primitive encode == published malformed wire -> error
//! ```

use super::{
    bindings, guard, original, publication, retirement,
    wire::{self, Value, a, b, bytes, m, s, u},
};
use terrane_format::gc::publication::{evidence::*, *};

/// Checks each independently reconstructed negative against its owning decoder.
///
/// # Panics
/// Panics for reference mismatches or accepted malformed data.
pub(super) fn check_models() {
    let mut input = bindings::primitive("local");
    input.array_mut()[1] = bytes(b"/a/../b");
    wire::reject("local-path", input.encode(), BackendBinding::decode);

    let mut input = bindings::primitive("s3");
    input.array_mut()[1] = s("azure");
    wire::reject("provider", input.encode(), BackendBinding::decode);

    let mut input = bindings::primitive("s3");
    input.array_mut()[2].array_mut()[0] = s("");
    wire::reject("endpoint-empty", input.encode(), BackendBinding::decode);

    let mut input = bindings::primitive("s3");
    input.array_mut()[2].array_mut()[2] = bytes(vec![0; 4097]);
    wire::reject("prefix-bound", input.encode(), BackendBinding::decode);

    let mut input = bindings::primitive("s3");
    input.array_mut()[2].array_mut()[3] = b(3, 31);
    wire::reject("nonce-short", input.encode(), BackendBinding::decode);

    for (label, phase) in [("active-null", 1), ("activation", 2)] {
        let input = m(vec![
            (0, u(1)),
            (1, bindings::primitive("local")),
            (2, u(phase)),
            (3, Value::Null),
        ]);
        wire::reject(label, input.encode(), BackendRegistration::decode);
    }
    let mut input = original::physical_wire("local");
    input.array_mut()[0] = u(2);
    wire::reject(
        "local-version",
        input.encode(),
        LocalOriginalRegistration::decode,
    );

    let mut input = original::physical_wire("s3");
    input.array_mut()[3] = bindings::primitive("local");
    wire::reject("remote-local", input.encode(), PhysicalRegistration::decode);

    let mut input = original::bootstrap_wire(false);
    input.array_mut()[4].array_mut()[0].array_mut()[1] = u(32);
    wire::reject("acl-mask", input.encode(), OriginalBootstrap::decode);

    wire::reject(
        "import-v1-remote",
        original::import_wire("s3", 1).encode(),
        OriginalImport::decode,
    );
    let mut input = original::import_wire("local", 2);
    input.array_mut()[3].array_mut()[2] = b(99, 32);
    wire::reject("import-id", input.encode(), OriginalImport::decode);

    wire::reject(
        "trust-version",
        a(vec![
            u(2),
            b(1, 32),
            b(1, 32),
            b(15, 32),
            a(vec![]),
            a(vec![]),
        ])
        .encode(),
        OriginalImportTrust::decode,
    );
    let mut issuers = original::issuers_wire();
    issuers.array_mut().reverse();
    wire::reject(
        "issuers-order",
        a(vec![
            u(1),
            b(1, 32),
            b(1, 32),
            b(15, 32),
            issuers,
            original::disclosures_wire(),
        ])
        .encode(),
        OriginalImportTrust::decode,
    );
    wire::reject(
        "disclosure-interval",
        a(vec![s("01".repeat(32)), s("public"), b(7, 32), u(2), u(2)]).encode(),
        DisclosureRow::decode,
    );

    let mut input = guard::config_wire(2);
    input.replace(5, u(1));
    wire::reject("config-minimum", input.encode(), TrustedGuardConfig::decode);
    let mut input = guard::registry_wire();
    input.replace(3, u(3));
    wire::reject(
        "registry-revision",
        input.encode(),
        ConfiguredRegistryInputs::decode,
    );
    let mut input = guard::registry_wire();
    input.replace(8, a(vec![s("acl")]));
    wire::reject(
        "registry-overlap",
        input.encode(),
        ConfiguredRegistryInputs::decode,
    );
    let mut input = guard::primitive("local", 0);
    input.field_mut(4).replace(6, s("private:elsewhere"));
    wire::reject("guard-domain", input.encode(), GuardSnapshot::decode);

    let mut input = publication::snapshot_wire("local", 0);
    input.field_mut(3).array_mut().remove(0);
    wire::reject(
        "snapshot-inventory",
        input.encode(),
        PortableSnapshot::decode,
    );
    let mut input = publication::snapshot_wire("local", 0);
    input.field_mut(3).array_mut()[1].array_mut()[1] = bytes(vec![]);
    wire::reject("snapshot-lease", input.encode(), PortableSnapshot::decode);
    let mut input = publication::snapshot_wire("local", 0);
    input
        .field_mut(3)
        .array_mut()
        .last_mut()
        .unwrap_or_else(|| panic!("full checkpoint fixture lacks its final row"))
        .array_mut()[1] = bytes(publication::head_wire().encode());
    wire::reject(
        "snapshot-selection",
        input.encode(),
        PortableSnapshot::decode,
    );
    let mut input = publication::snapshot_wire("local", 1);
    input.replace(1, u(2));
    wire::reject("delta-revision", input.encode(), PortableSnapshot::decode);

    let mut input = publication::genesis_wire("local");
    input.field_mut(4).array_mut().remove(0);
    wire::reject(
        "genesis-inventory",
        input.encode(),
        PublicationTransaction::decode,
    );
    let mut input = publication::genesis_wire("local");
    input.field_mut(4).array_mut()[0].array_mut()[1] = bytes(vec![]);
    wire::reject(
        "genesis-expected",
        input.encode(),
        PublicationTransaction::decode,
    );
    let mut input = publication::genesis_wire("local");
    input.field_mut(7).array_mut()[0] = s(format!("publication/snapshots/0:{}", "00".repeat(32)));
    wire::reject(
        "genesis-nonce",
        input.encode(),
        PublicationTransaction::decode,
    );
    wire::reject(
        "commit-predecessor",
        m(vec![
            (0, u(1)),
            (1, u(1)),
            (2, Value::Null),
            (
                3,
                s(format!("publication/transactions/{}", "34".repeat(32))),
            ),
            (4, b(17, 32)),
        ])
        .encode(),
        PublicationCommit::decode,
    );
    let mut input = publication::state_wire("local", 0);
    input.replace(6, Value::Null);
    wire::reject("state-guard", input.encode(), PublicationState::decode);

    let mut input = retirement::collection_wire(false, false);
    input.array_mut()[3]
        .array_mut()
        .push(a(vec![b(0x12, 16), b(99, 32)]));
    wire::reject("proof-index", input.encode(), PublicationProof::decode);
    let mut carried = retirement::carried_wire();
    carried.array_mut().reverse();
    wire::reject(
        "proof-carried-order",
        a(vec![u(2), s("gc/3/fence/2"), b(20, 32), a(vec![]), carried]).encode(),
        PublicationProof::decode,
    );
    wire::reject(
        "proof-copy-lineage",
        a(vec![
            u(3),
            bytes(retirement::authorization_wire("remote", false).encode()),
            a(vec![a(vec![s(publication::NAME), b(23, 32)])]),
        ])
        .encode(),
        PublicationProof::decode,
    );
    wire::reject(
        "proof-tag",
        a(vec![u(5)]).encode(),
        PublicationProof::decode,
    );

    let base = bindings::primitive("local").encode();
    let mut trailing = base.clone();
    trailing.push(0);
    let mut nonminimal = vec![0x98, 6];
    nonminimal.extend(&base[1..]);
    let mut huge_array = vec![0x9b];
    huge_array.extend([0xff; 8]);
    let mut huge_bytes = vec![0x86, 0, 0x5b];
    huge_bytes.extend([0xff; 8]);
    for (name, wire) in [
        ("truncated", base[..base.len() - 1].to_vec()),
        ("trailing", trailing),
        ("nonminimal", nonminimal),
        ("huge-array", huge_array),
        ("huge-bytes", huge_bytes),
    ] {
        wire::reject(name, wire, BackendBinding::decode);
    }
}
