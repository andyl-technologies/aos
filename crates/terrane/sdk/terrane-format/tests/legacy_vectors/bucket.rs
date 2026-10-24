//! Executes every D-80 capabilities/generation witness and the second tombstone codec.

use super::support::{digest, wire};
use terrane_format::{
    bucket::{
        BucketCapabilities, GenerationManifest, GenerationShard, PackExclusion, PackInventoryEntry,
        StoreProfile,
    },
    cbor, gc,
};

/// Returns the published sixteen-byte pack identifier containing bytes zero to fifteen.
pub(super) fn pack_id() -> [u8; 16] {
    core::array::from_fn(|index| u8::try_from(index).unwrap())
}

/// Compares the complete legacy capabilities model with its published wire bytes.
///
/// # Panics
/// Panics if fixture extraction or codec execution fails, or bytes/model fields differ.
pub(super) fn capabilities() {
    let model = BucketCapabilities {
        layout_version: 2,
        create_if_absent: true,
        compare_and_swap: true,
        ranges: true,
        presign: false,
        multi_writer: true,
        probed_at: 1_760_000_000,
        profile: StoreProfile {
            identity: "terrane-v1".into(),
            algorithm: "blake3".into(),
            chunk: "cdc-1m".into(),
            seed: [0; 32],
        },
        generation: Some(7),
        ref_names: Some(vec!["refs/heads/pr/1234".into(), "refs/tags/_/v1".into()]),
        publication_protocol: None,
    };
    let published = wire("### Capabilities v2", 0);

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(BucketCapabilities::decode(&published).unwrap(), model);
}

fn generation_model() -> GenerationManifest {
    GenerationManifest {
        generation: 7,
        shards: vec![GenerationShard {
            shard: 148,
            index_hash: digest("757c166a37cd1ce27ac689b8542a7a0ccf854ebb3faabbe5f1c476dc004bcd8a"),
            index_size: 84,
            filter: None,
        }],
        written_at: 1_760_000_000,
        cycle: 7,
        inventory: Some(vec![PackInventoryEntry {
            pack_id: pack_id(),
            pack_hash: digest("a832ebdf8d5c85eaa46b6323220a0ff42449c384d05b7dd65b00b807aecc5f44"),
            pack_size: 181,
            index_hash: digest("7c0fa339c9072256d2f6537294a4ca55086523971d5c68cf27794d8196f9dc3a"),
            index_size: 148,
        }]),
        exclusions: Some(vec![]),
        burns: None,
    }
}

/// Reproduces the negative generation model directly, including its null key 6.
fn generation_with_null_exclusions() -> Vec<u8> {
    let model = generation_model();
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 6);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, model.generation);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, model.shards.len());
    for shard in &model.shards {
        cbor::write_array(&mut bytes, 3);
        cbor::write_uint(&mut bytes, shard.shard);
        cbor::write_bytes(&mut bytes, &shard.index_hash);
        cbor::write_uint(&mut bytes, shard.index_size);
    }
    cbor::write_uint(&mut bytes, 3);
    cbor::write_uint(&mut bytes, model.written_at);
    cbor::write_uint(&mut bytes, 4);
    cbor::write_uint(&mut bytes, model.cycle);
    cbor::write_uint(&mut bytes, 5);
    let inventory = model.inventory.unwrap();
    cbor::write_array(&mut bytes, inventory.len());
    for entry in &inventory {
        cbor::write_array(&mut bytes, 5);
        cbor::write_bytes(&mut bytes, &entry.pack_id);
        cbor::write_bytes(&mut bytes, &entry.pack_hash);
        cbor::write_uint(&mut bytes, entry.pack_size);
        cbor::write_bytes(&mut bytes, &entry.index_hash);
        cbor::write_uint(&mut bytes, entry.index_size);
    }
    cbor::write_uint(&mut bytes, 6);
    bytes.push(0xf6);

    bytes
}

/// Checks published generation exclusion models and rejects the literal null control.
///
/// # Panics
/// Panics if fixtures or codec execution fail, positive bytes/models differ, or
/// the independently assembled null-exclusions control is accepted.
pub(super) fn generations() {
    let empty = generation_model();
    let mut exclusions = empty.clone();
    exclusions.exclusions = Some(vec![PackExclusion {
        pack_id: pack_id(),
        cycle: 7,
        epoch: 2,
    }]);
    let only = GenerationManifest {
        generation: 8,
        shards: vec![],
        written_at: 1_760_000_003,
        cycle: 7,
        inventory: None,
        exclusions: exclusions.exclusions.clone(),
        burns: None,
    };

    for (heading, model) in [
        ("### Index generation exclusions empty", empty),
        ("### Index generation exclusions", exclusions),
        ("### Index generation exclusions only", only),
    ] {
        let published = wire(heading, 0);
        assert_eq!(model.encode().unwrap(), published, "{heading}");
        assert_eq!(
            GenerationManifest::decode(&published).unwrap(),
            model,
            "{heading}"
        );
    }

    let negative = generation_with_null_exclusions();
    assert_eq!(negative, wire("### Index generation null exclusions", 0));
    assert!(GenerationManifest::decode(&negative).is_err());
}

/// Compares the collector tombstone model with its published encoding.
///
/// # Panics
/// Panics if fixture extraction or decoding fails, or encoded bytes/model fields differ.
pub(super) fn collector_tombstone() {
    let model = gc::Tombstone {
        pack: pack_id(),
        cycle: 7,
        timestamp: 24,
        removed: 2,
        epoch: 9,
    };
    let published = wire("### collection-tombstone", 0);

    assert_eq!(model.encode(), published);
    assert_eq!(gc::Tombstone::decode(&published).unwrap(), model);
}
