//! Names the actual pinned JSON Value equality controls independently of serde.
//!
//! Value's derived PartialEq descends into Vec slices and the selected Map. AOS
//! pins serde_json1.0.150's default BTreeMap representation; the matching Rust
//! 1.98.1 map equality zips borrowed entries. This helper neither walks a Value
//! nor allocates backing, and makes no physical process-stack claim.

use crate::node_contract::NodeRuntime;
use serde_json::{Map, Number, Value};
use std::{
    collections::btree_map,
    mem::{Discriminant, size_of},
};

type Entry<'a> = (&'a String, &'a Value);
type MapIterator<'a> = btree_map::Iter<'a, String, Value>;

impl NodeRuntime {
    /// Names one recursive JSON Value equality frame without comparing values.
    ///
    /// A caller independently multiplies this declaration by the established
    /// reachable comparison depth, including terminal scalar/nullable frames.
    /// RawValue reset-parser depth is not assumed to remain the original64.
    /// Parser, serde adapters, reencoding, canonical sorting and all existing
    /// Value/string/map owners remain separate constructor demand. The selected
    /// serde Map/std equality source pins belong to the supplier manifest.
    pub fn capture_json_value_equality_frame_counter_scratch_data() -> usize {
        // Derived Value variant dispatch and the outer Option<&Value> comparison
        // carry only borrowed discriminants/options/scalars, never a Value copy.
        2 * size_of::<&Value>()
            + 2 * size_of::<Discriminant<Value>>()
            + 2 * size_of::<Option<&Value>>()
            + 2 * size_of::<&bool>()
            + 2 * size_of::<&Number>()
            + 2 * size_of::<&String>()
            + 2 * size_of::<&Vec<Value>>()
            + 2 * size_of::<&Map<String, Value>>()
            // Vec delegates to the actual index-based slice comparison: two
            // pointers, len and idx (Rust1.98.1 explicitly avoids zipped iterators).
            + 2 * size_of::<&[Value]>()
            + 2 * size_of::<*const Value>()
            + 2 * size_of::<usize>()
            // BTreeMap::eq really does zip entry iterators after checking len.
            + 2 * size_of::<Option<&Value>>()
            + size_of::<std::iter::Zip<MapIterator<'static>, MapIterator<'static>>>()
            + 2 * size_of::<Entry<'static>>()
            + 2 * size_of::<Option<Entry<'static>>>()
            + size_of::<Option<(Entry<'static>, Entry<'static>)>>()
            // Actual String/str equality borrows its two byte slices; Number
            // compares its two selected native scalar values without formatting.
            + 2 * size_of::<&str>()
            + 2 * size_of::<&[u8]>()
            + 2 * size_of::<usize>()
            + 2 * size_of::<f64>()
            + 2 * size_of::<u64>()
            + 2 * size_of::<i64>()
            + size_of::<bool>()
    }
}
