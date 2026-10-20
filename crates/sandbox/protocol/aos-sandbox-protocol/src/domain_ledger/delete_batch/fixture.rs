//! Supplies passive synthetic Delete bytes for codec and replay tests.

use super::*;

/// Supplies purely synthetic canonical DATA to the selected codec tests.
///
/// This fixture carries no provenance, currentness or append permission. Callers
/// supply a nonempty key of at most 1024 bytes and an ordinary retained sequence;
/// unsupported inputs may produce malformed DATA.
///
/// # Panics
///
/// Panics if unchecked length arithmetic or synthetic row-layout indexing exceeds
/// its representable bounds. The fixture retains its original unchecked recipe.
pub fn fixture_batch_v1(key: &[u8], before: &[u8], sequence: u64) -> Vec<u8> {
    let length = 640 + 100 + key.len() + 17;
    let mut bytes = vec![0; length];
    bytes[..8].copy_from_slice(b"AOSDEL01");
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&(length as u32).to_be_bytes());
    bytes[16..32].fill(4);
    bytes[32..48].fill(5);
    bytes[48..64].fill(6);
    bytes[64] = 1;
    bytes[65..81].fill(7);
    bytes[88..96].copy_from_slice(&sequence.to_be_bytes());
    bytes[96..104].copy_from_slice(&1_u64.to_be_bytes());
    bytes[104..264].fill(8);
    bytes[296..300].copy_from_slice(&1_u32.to_be_bytes());
    bytes[312..316].copy_from_slice(&1_u32.to_be_bytes());
    for (index, row) in bytes[320..608].chunks_exact_mut(48).enumerate() {
        row[0] = index as u8 + 1;
        row[4..12].copy_from_slice(&1_u64.to_be_bytes());
        row[16..48].fill(10 + index as u8);
    }
    let write_end = 708 + key.len();
    bytes[608] = 1;
    bytes[609..625].fill(7);
    bytes[625] = 1;
    bytes[626..628].copy_from_slice(&(key.len() as u16).to_be_bytes());
    bytes[628..636].copy_from_slice(&1_u64.to_be_bytes());
    bytes[636..668].copy_from_slice(&native_value_digest(before));
    bytes[668..676].copy_from_slice(&2_u64.to_be_bytes());
    bytes[708..write_end].copy_from_slice(key);
    bytes[write_end] = 1;
    bytes[write_end + 1..write_end + 17].fill(7);

    let (graph, after) = {
        let empty = &bytes[0..0];
        let view = DeleteBatchViewV1 {
            bytes: &bytes,
            sections: [
                &bytes[608..write_end],
                empty,
                empty,
                empty,
                &bytes[write_end..write_end + 17],
            ],
            counts: [1, 0, 0, 0, 1],
            companions: empty,
        };
        (
            view.graph_digest(),
            native_value_digest(&tombstone(view, &bytes[608..write_end])),
        )
    };
    bytes[264..296].copy_from_slice(&graph);
    bytes[676..708].copy_from_slice(&after);
    seal(&mut bytes, BATCH_DOMAIN);
    bytes
}
