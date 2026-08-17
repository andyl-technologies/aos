//! Demand graph tests.

use super::*;
use crate::cache::hashing::{DemandKeyConfirmationHash, DemandKeyHotHash};
use crate::cache::{
    CacheExprIdentity, CacheExprSourceHash, DurableBlake3Hash, ImpureInputFingerprint,
    UncacheableInput,
};
use crate::compile::IrId;
use crate::value::{HeapObject, Value, ValueTag};
use std::ptr::NonNull;

mod frontier;
mod impure_input;
mod impure_trace;
mod keys_edges;
mod reconsideration;

fn value_hash(bytes: &[u8]) -> ValueHash {
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
}

fn inline_value_hash(value: Value) -> ValueHash {
    ValueHash::from_inline_value(value).expect("inline value hashes")
}

fn derivation_aterm_hash(aterm: &[u8]) -> ValueHash {
    ValueHash::from_derivation_aterm_bytes(aterm)
}

fn durable_hash(bytes: &[u8]) -> DurableBlake3Hash {
    DurableBlake3Hash::for_bytes(bytes)
}

fn demand_hot(raw: u64) -> DemandKeyHotHash {
    DemandKeyHotHash::from_xxh3(raw)
}

fn demand_confirmation(bytes: &[u8]) -> DemandKeyConfirmationHash {
    DemandKeyConfirmationHash::from_precomputed_hash(durable_hash(bytes))
}

fn expr_source_hash(bytes: &[u8]) -> CacheExprSourceHash {
    CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes))
}

fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
    CacheExprIdentity::new(expr_source_hash(source), IrId::new(node))
}

fn key(node: u32, label: &[u8]) -> DemandCacheKey {
    DemandCacheKey::for_free_vars(identity(label, node), [value_hash(label)]).expect("key builds")
}

fn read_file_input(path: &[u8], contents: &[u8]) -> CacheableInputFingerprint {
    ImpureInputFingerprint::read_file(path, contents)
        .expect("input fingerprints")
        .as_cacheable()
        .expect("readFile is cacheable")
        .clone()
}

fn read_file_trace(path: &[u8], contents: &[u8]) -> ImpureInputFingerprint {
    ImpureInputFingerprint::read_file(path, contents).expect("input fingerprints")
}

fn node_with_hash(graph: &mut DemandGraph, node: u32, label: &'static [u8]) -> DemandNodeId {
    graph
        .get_or_insert_node(key(node, label), Some(value_hash(label)))
        .expect("node inserts")
}
