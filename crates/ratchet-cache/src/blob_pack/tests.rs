use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

mod appender;
mod mapped;
mod reader;

const FROZEN_EMPTY_BLOB_PACK: [u8; BLOB_PACK_HEADER_LEN + BLOB_RECORD_HEADER_LEN] = [
    b'A', b'O', b'S', b'-', b'N', b'I', b'X', b'-', b'B', b'L', b'O', b'B', b'P', b'A', b'C', b'K',
    1, 0, 0, 0, 24, 0, 0, 0, 0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d,
    0xea, 0x36, 0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93,
    0xca, 0xe4, 0x1f, 0x32, 0x62, 0, 0, 0, 0, 0, 0, 0, 0,
];

struct FrozenTestLease;

// SAFETY: Tests only use this lease after writing a temporary pack fully
// and perform no mutation until after the leased mapping is dropped.
unsafe impl BlobPackReadLease for FrozenTestLease {
    fn covers_file(&self, _file: &fs::File) -> bool {
        true
    }
}

struct RejectingTestLease;

// SAFETY: This lease never covers any file, so it never asserts an
// immutability guarantee.
unsafe impl BlobPackReadLease for RejectingTestLease {
    fn covers_file(&self, _file: &fs::File) -> bool {
        false
    }
}

fn temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ratchet-cache-blob-pack-{name}-{}-{nonce}.tmp",
        std::process::id()
    ))
}

fn write_pack(path: &PathBuf, records: &[&[u8]]) -> Vec<BlobPackLocation> {
    let mut file = fs::File::create(path).expect("pack file creates");
    file.write_all(&BlobPackHeader::current().encode())
        .expect("pack header writes");
    let mut offset = BLOB_PACK_HEADER_LEN as u64;
    let mut locations = Vec::new();
    for payload in records {
        let hash = BlobPackHash::for_bytes(payload);
        let payload_len = u64::try_from(payload.len()).expect("payload length fits");
        file.write_all(&BlobRecordHeader::new(hash, payload_len).encode())
            .expect("record header writes");
        file.write_all(payload).expect("payload writes");
        locations.push(BlobPackLocation::new(offset, payload_len));
        offset += BLOB_RECORD_HEADER_LEN as u64 + payload_len;
    }
    file.sync_all().expect("pack file syncs");
    locations
}

fn map_pack(path: &PathBuf) -> MappedBlobPack {
    let file = fs::File::open(path).expect("pack opens read-only");
    unsafe {
        // SAFETY: Each test writes the pack completely before mapping and
        // performs no mutation until after the mapping is dropped.
        MappedBlobPack::map_file(&file)
    }
    .expect("pack maps")
}
