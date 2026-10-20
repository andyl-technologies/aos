//! Checks independently assembled canonical D-82 records and pure refusal paths.
//!
//! Fixtures use primitive CBOR writers and hand-transcribed registered field
//! layouts, never the production record codecs to construct expected bytes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod authorization;
mod fence;
mod progress;

use super::*;
use crate::cbor::{write_array, write_bytes, write_map, write_text, write_uint};
use alloc::{format, vec};

const PACK: [u8; 16] = [0x12; 16];
const NONCE: [u8; 32] = [0x34; 32];
const LEASE: &[u8] = &[0xa3, 1, 0x61, b'A', 2, 2, 3, 0x18, 100];

fn remote() -> BackendBinding {
    BackendBinding::Remote {
        provider: super::super::publication::RemoteProvider::S3,
        endpoint: "e".into(),
        bucket: "b".into(),
        prefix: vec![],
        resource_nonce: [1; 32],
        coordination_key: b"c".to_vec(),
        coordination_nonce: [2; 32],
    }
}

fn remote_bytes() -> Vec<u8> {
    let mut bytes = vec![
        0x84, 1, 0x62, b's', b'3', 0x84, 0x61, b'e', 0x61, b'b', 0x40, 0x58, 0x20,
    ];
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[0x82, 0x41, b'c', 0x58, 0x20]);
    bytes.extend_from_slice(&[2; 32]);
    bytes
}

fn local_bytes() -> Vec<u8> {
    vec![0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4]
}

fn exclusion() -> Exclusion {
    Exclusion {
        pack: PACK,
        cycle: 3,
        epoch: 2,
    }
}

fn key() -> String {
    format!("gc/3/delete/{}/{}", "12".repeat(16), "34".repeat(32))
}

fn artifact_key(index: bool) -> String {
    format!(
        "objects/pack/12/{}.{}",
        "12".repeat(16),
        if index { "idx" } else { "pack" }
    )
}

fn trash_key() -> String {
    format!("trash/3/{}", "12".repeat(16))
}

fn tombstone_bytes() -> Vec<u8> {
    let mut bytes = vec![0xa5, 1, 0x50];
    bytes.extend_from_slice(&PACK);
    bytes.extend_from_slice(&[2, 3, 3, 4, 4, 0, 5, 2]);
    bytes
}

fn witness_bytes() -> Vec<u8> {
    let mut bytes = b"TRPK\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&PACK);
    bytes.extend_from_slice(b"TRIX\0\0\0\0\0\0\0\0");
    bytes
}

fn index_digest() -> RawDigest {
    let mut hash = blake3::Hasher::new();
    hash.update(b"terrane-index-v1\0");
    hash.update(&witness_bytes());
    *hash.finalize().as_bytes()
}

fn field(bytes: &mut Vec<u8>, key: u64, value: u64) {
    write_uint(bytes, key);
    write_uint(bytes, value);
}

fn pointer(bytes: &mut Vec<u8>, key: &str, digest: RawDigest) {
    write_array(bytes, 2);
    write_text(bytes, key);
    write_bytes(bytes, &digest);
}

fn slot(bytes: &mut Vec<u8>, revision: u64, digest: RawDigest) {
    write_array(bytes, 2);
    write_uint(bytes, revision);
    write_bytes(bytes, &digest);
}

fn artifact(bytes: &mut Vec<u8>, key: &str, digest: RawDigest, size: u64) {
    write_array(bytes, 3);
    write_text(bytes, key);
    write_bytes(bytes, &digest);
    write_uint(bytes, size);
}

fn exclusion_bytes(bytes: &mut Vec<u8>) {
    write_array(bytes, 3);
    write_bytes(bytes, &PACK);
    write_uint(bytes, 3);
    write_uint(bytes, 2);
}

fn auth_bytes(copy: bool, local: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_map(&mut bytes, if copy { 16 } else { 14 });
    field(&mut bytes, 0, 2);
    write_uint(&mut bytes, 1);
    write_bytes(&mut bytes, &NONCE);
    write_uint(&mut bytes, 2);
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    write_uint(&mut bytes, 3);
    exclusion_bytes(&mut bytes);
    write_uint(&mut bytes, 4);
    bytes.extend_from_slice(LEASE);
    field(&mut bytes, 5, 2);
    write_uint(&mut bytes, 6);
    write_array(&mut bytes, 3);
    if copy {
        bytes.extend_from_slice(&[0xf6, 0xf6]);
        if local {
            write_array(&mut bytes, 4);
            write_text(&mut bytes, &trash_key());
            write_bytes(&mut bytes, &[5; 32]);
            write_array(&mut bytes, 2);
            write_uint(&mut bytes, 2);
            write_bytes(&mut bytes, &tombstone_bytes());
            write_bytes(&mut bytes, &[6]);
        } else {
            artifact(
                &mut bytes,
                &trash_key(),
                *blake3::hash(&tombstone_bytes()).as_bytes(),
                tombstone_bytes().len() as u64,
            );
        }
    } else {
        artifact(&mut bytes, &artifact_key(false), [7; 32], 52);
        artifact(&mut bytes, &artifact_key(true), index_digest(), 36);
        artifact(
            &mut bytes,
            &trash_key(),
            *blake3::hash(&tombstone_bytes()).as_bytes(),
            tombstone_bytes().len() as u64,
        );
        write_uint(&mut bytes, 7);
        write_bytes(&mut bytes, &witness_bytes());
    }
    write_uint(&mut bytes, 8);
    write_bytes(&mut bytes, &tombstone_bytes());
    field(&mut bytes, 9, 2_000_000_000);
    write_uint(&mut bytes, 10);
    pointer(&mut bytes, "gc/3/fence/2", [8; 32]);
    field(&mut bytes, 11, 1);
    field(&mut bytes, 12, 1_000_000_000);
    field(&mut bytes, 13, 1);
    if copy {
        field(&mut bytes, 14, 1);
        write_uint(&mut bytes, 15);
        slot(&mut bytes, 0, [9; 32]);
        write_uint(&mut bytes, 16);
        slot(&mut bytes, 1, [10; 32]);
    }
    bytes
}

fn plan_bytes(local: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_map(&mut bytes, 10);
    field(&mut bytes, 0, 2);
    write_uint(&mut bytes, 1);
    write_bytes(&mut bytes, &NONCE);
    write_uint(&mut bytes, 2);
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    write_uint(&mut bytes, 3);
    exclusion_bytes(&mut bytes);
    write_uint(&mut bytes, 4);
    bytes.extend_from_slice(LEASE);
    write_uint(&mut bytes, 5);
    slot(&mut bytes, 0, [9; 32]);
    write_uint(&mut bytes, 6);
    pointer(&mut bytes, "gc/3/fence/0", [11; 32]);
    write_uint(&mut bytes, 7);
    write_bytes(&mut bytes, &tombstone_bytes());
    field(&mut bytes, 8, 1);
    field(&mut bytes, 9, 2);
    bytes
}

fn state_bytes(revision: u64, digest: RawDigest, local: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_map(&mut bytes, 8);
    field(&mut bytes, 0, 1);
    field(&mut bytes, 1, revision);
    field(&mut bytes, 2, 1);
    write_uint(&mut bytes, 3);
    write_array(&mut bytes, 0);
    write_uint(&mut bytes, 4);
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    write_uint(&mut bytes, 5);
    write_array(&mut bytes, 0);
    field(&mut bytes, 6, 0);
    bytes.pop();
    bytes.push(0xf6);
    write_uint(&mut bytes, 7);
    write_array(&mut bytes, 1);
    write_array(&mut bytes, 2);
    write_bytes(&mut bytes, &PACK);
    write_array(&mut bytes, 3);
    write_uint(&mut bytes, 1);
    write_text(&mut bytes, &key());
    write_bytes(&mut bytes, &digest);
    bytes
}

fn pass_bytes(local: bool) -> Vec<u8> {
    let digest = *blake3::hash(&auth_bytes(local, local)).as_bytes();
    let mut bytes = Vec::new();
    write_map(&mut bytes, if local { 14 } else { 13 });
    field(&mut bytes, 0, 2);
    write_uint(&mut bytes, 1);
    write_bytes(&mut bytes, &digest);
    write_uint(&mut bytes, 2);
    slot(&mut bytes, 3, [12; 32]);
    field(&mut bytes, 3, if local { 2 } else { 1 });
    write_uint(&mut bytes, 4);
    write_array(&mut bytes, 2);
    write_uint(&mut bytes, 0);
    write_uint(&mut bytes, 0);
    write_uint(&mut bytes, 5);
    slot(&mut bytes, 4, [13; 32]);
    write_uint(&mut bytes, 6);
    write_bytes(&mut bytes, &state_bytes(4, digest, local));
    write_uint(&mut bytes, 7);
    bytes.extend_from_slice(LEASE);
    write_uint(&mut bytes, 8);
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    field(&mut bytes, 9, 0);
    write_uint(&mut bytes, 10);
    write_array(&mut bytes, 0);
    write_uint(&mut bytes, 11);
    write_array(&mut bytes, 3);
    for kind in 0..3 {
        write_array(&mut bytes, 2);
        write_uint(&mut bytes, kind);
        write_uint(&mut bytes, 0);
    }
    write_uint(&mut bytes, 12);
    write_bytes(&mut bytes, &[14; 32]);
    if local {
        write_uint(&mut bytes, 13);
        pointer(&mut bytes, "gc/3/fence/4", [15; 32]);
    }
    bytes
}
