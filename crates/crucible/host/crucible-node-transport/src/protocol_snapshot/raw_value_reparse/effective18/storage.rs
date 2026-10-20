//! Quotes and observes the actual flat/text effective-pass workspace.
//!
//! Lexical occurrences and Raw4 reset-layer geometry independently bound every
//! initialized text, node, edge and parser frame. No protocol/native cap becomes
//! heap demand. Caller admission beside all old owners remains mandatory.

use super::*;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};

/// Binds one actual immutable text extent to independently requested workspace.
///
/// The private producer alone constructs this DATA row. Matching it is neither
/// an admission, actor/currentness proof nor a permission to parse another bank.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18EffectiveTextConstructionData {
    input: *const u8,
    length: usize,
    pub(super) nodes: usize,
    pub(super) text_slots: usize,
    pub(super) text_bytes: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeImport18EffectiveTextConstructionData {
    /// Quotes actual text lexical populations without decoding or allocation.
    ///
    /// The caller admits counter_scratch_data BEFORE this quote, then admits
    /// every returned axis beside all existing owners before read_into_data.
    /// The original maximum is a bound on this new row, never a byte donor.
    ///
    /// # Errors
    /// Refuses checked overflow, unsupported tree layout or requested overflow.
    pub(crate) fn quote_data(
        input: &str,
        maximum_requested_bytes: usize,
    ) -> Result<Self, ProviderError> {
        let extent = input.len().max(1);
        let lexical = original_json_value_storage_extent_data(extent)?;
        // Exactly the existing Raw4 quote proof: each nested encoded Raw string
        // adds escaping, so a chain has at most log2(actual extent)+1 resets.
        // The initial text parser is a separate level, not a donated allowance.
        let levels = add(geometry::maximum_layers_data(extent)?, 1)?;
        let nodes = mul(levels, lexical.maximum_value_nodes)?;
        let text_slots = add(1, mul(2, nodes)?)?;
        let text_bytes = add(
            input.len(),
            mul(levels, lexical.maximum_decoded_string_bytes)?,
        )?;
        let trees = tree_storage_data(
            nodes,
            nodes,
            size_of::<String>() + size_of::<usize>(),
            align_of::<String>().max(align_of::<usize>()),
        )?;
        let retained = sum(&[
            size_of::<Option<NativeImport18EffectiveTextAttemptData>>(),
            mul(nodes, size_of::<Node>())?,
            mul(nodes, size_of::<Edge>())?,
            mul(nodes, size_of::<Frame>())?,
            mul(text_slots, size_of::<String>())?,
            text_bytes,
            trees,
        ])?;

        // Scalar Number parsing uses the same actual locked text parser/error
        // machinery. Probe root+its literal null reparse are separately named,
        // fixed shallow owners and drop before user-text work begins.
        let (number_work, number_scratch) = geometry::parser_storage_data(extent)?;
        let probe = original_json_value_storage_extent_data(RAW_PROBE.len())?;
        let (probe_work, probe_scratch) = geometry::parser_storage_data(RAW_PROBE.len())?;
        let probe_root_and_payload = mul(2, add(probe.value_dom_requested_bytes, probe_work)?)?;
        let scalar_number = add(number_work, size_of::<Result<Number, serde_json::Error>>())?;
        let constructor_outputs = sum(&[
            size_of::<NativeImport18EffectiveTextAttemptData>(),
            size_of::<Option<NativeImport18EffectiveTextAttemptData>>(),
            size_of::<Node>(),
            size_of::<Kind>(),
            size_of::<BTreeMap<String, usize>>(),
        ])?;
        // BTreeMap::insert can construct a root or split nodes while the
        // retained tree is still live. Its independent constructor window uses
        // the same pinned node classes and actual lexical populations; retained
        // tree backing above does not fund this temporary construction.
        let tree_constructor_transient = tree_storage_data(
            nodes,
            nodes,
            size_of::<String>() + size_of::<usize>(),
            align_of::<String>().max(align_of::<usize>()),
        )?;
        let transient = constructor_outputs
            .max(tree_constructor_transient)
            .max(probe_root_and_payload)
            .max(scalar_number);
        let scratch = add(
            Self::counter_scratch_data(),
            number_scratch.max(mul(2, probe_scratch)?),
        )?;
        if sum(&[retained, transient, scratch])? > maximum_requested_bytes {
            return Err(exhausted());
        }
        Ok(Self {
            input: input.as_ptr(),
            length: input.len(),
            nodes,
            text_slots,
            text_bytes,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn authenticate_data(&self, input: &str) -> Result<(), ProviderError> {
        if self.input != input.as_ptr() || self.length != input.len() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Returns independent retained workspace growth, including its root slot.
    pub(crate) const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independent tree/scalar/probe/initializer construction demand.
    pub(crate) const fn transient_requested_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the complete defining quote/parser/workspace controls.
    pub(crate) const fn declared_counter_scratch_data(&self) -> usize {
        self.scratch
    }

    /// Names actual lexical/iterator/partial/layout controls before a prewalk.
    pub(crate) fn counter_scratch_data() -> usize {
        native_import18_json_lexical_counter_scratch_data()
            + original_json_value_storage_extent_counter_scratch_data()
            + geometry::quote_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&NativeImport18EffectiveTextAttemptData>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<OriginalJsonValueStorageExtentData>() * 2
            + size_of::<NativeImport18EffectiveTextAttemptData>()
            + size_of::<Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&mut Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&mut NativeImport18EffectiveTextAttemptData>()
            + size_of::<Option<&mut NativeImport18EffectiveTextAttemptData>>()
            + size_of::<Result<&mut NativeImport18EffectiveTextAttemptData, ProviderError>>()
            + size_of::<RawMode>()
            + size_of::<Option<RawMode>>()
            + size_of::<Result<RawMode, ProviderError>>()
            + size_of::<Value>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Number>()
            + size_of::<Result<Number, serde_json::Error>>()
            + size_of::<Node>()
            + size_of::<Kind>()
            + size_of::<&Node>()
            + size_of::<Option<&Node>>()
            + size_of::<Result<&Node, ProviderError>>()
            + size_of::<&Kind>()
            + size_of::<&Edge>()
            + size_of::<Option<&Edge>>()
            + size_of::<Edge>()
            + size_of::<Frame>()
            + size_of::<Option<Frame>>()
            + size_of::<Job>()
            + size_of::<Option<Job>>()
            + size_of::<Returned>()
            + size_of::<Option<Returned>>()
            + size_of::<Result<Returned, ProviderError>>()
            + size_of::<Lexical>()
            + size_of::<(Lexical, usize)>()
            + size_of::<Result<(Lexical, usize), ProviderError>>()
            + size_of::<Vec<String>>()
            + size_of::<String>()
            + size_of::<&mut String>()
            + size_of::<&mut usize>()
            + size_of::<&mut BTreeMap<String, usize>>()
            + size_of::<(String, usize)>()
            + size_of::<std::collections::btree_map::Entry<'static, String, usize>>()
            + size_of::<std::collections::btree_map::OccupiedEntry<'static, String, usize>>()
            + size_of::<std::collections::btree_map::VacantEntry<'static, String, usize>>()
            + size_of::<(&mut [String], &mut [String])>()
            + size_of::<Option<&String>>()
            + size_of::<&String>()
            + size_of::<Result<&String, ProviderError>>()
            + size_of::<Option<&str>>()
            + size_of::<Result<&str, ProviderError>>()
            + size_of::<&str>()
            + size_of::<&[u8]>()
            + size_of::<&usize>()
            + size_of::<[usize; 7]>()
            + size_of::<[usize; 5]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<std::slice::Iter<'static, String>>()
            + size_of::<std::slice::Iter<'static, Node>>()
            + size_of::<std::slice::Iter<'static, Edge>>()
            + size_of::<std::slice::Iter<'static, Frame>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, usize>>()
            + size_of::<(&String, &usize)>()
            + size_of::<Option<(&String, &usize)>>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<Option<&mut usize>>()
            + size_of::<Option<usize>>()
            + size_of::<NativeImport18EffectiveValueViewData<'static>>()
            + size_of::<NativeImport18EffectiveValueKindData<'static>>()
            + size_of::<EffectiveArray<'static>>()
            + size_of::<EffectiveObject<'static>>()
            + size_of::<&mut EffectiveArray<'static>>()
            + size_of::<&mut EffectiveObject<'static>>()
            + size_of::<Option<NativeImport18EffectiveValueViewData<'static>>>()
            + size_of::<(&str, NativeImport18EffectiveValueViewData<'static>)>()
            + size_of::<Option<(&str, NativeImport18EffectiveValueViewData<'static>)>>()
            + size_of::<Result<NativeImport18EffectiveValueKindData<'static>, ProviderError>>()
            + size_of::<Result<NativeImport18EffectiveValueViewData<'static>, ProviderError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            // Seventeen quote locals plus its maximum argument; the actual
            // census separately holds text/containers/members/trees/total and
            // its maximum argument. Helper scalar headers are not donors.
            + size_of::<usize>() * 24
    }
}

impl NativeImport18EffectiveTextAttemptData {
    /// Counts all initialized flat/text/work backing, including refused prefixes.
    ///
    /// The conservative pinned BTree layout counts actual nonempty containers
    /// and actual entries, not prospective row populations or serialized bytes.
    /// The root Option header is included; an enclosing inline owner avoids
    /// counting that same header twice while preserving every backing term.
    ///
    /// # Errors
    /// Refuses checked requested-layout overflow or the caller's whole bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            started: _,
            failed: _,
            complete: _,
            mode: _,
            row: _,
            texts,
            nodes,
            edges,
            frames,
            requested_text: _,
            inserted_members: _,
            maximum_intermediate_depth: _,
            root: _,
        } = self;
        let mut text = 0usize;
        let mut containers = 0usize;
        let mut members = 0usize;
        for value in texts {
            text = add(text, value.capacity())?;
        }
        for Node { kind } in nodes {
            match kind {
                Kind::Object(values) => {
                    if !values.is_empty() {
                        containers = add(containers, 1)?;
                    }
                    members = add(members, values.len())?;
                    for (key, _) in values {
                        text = add(text, key.capacity())?;
                    }
                }
                Kind::Null
                | Kind::Bool(_)
                | Kind::Number(_)
                | Kind::String(_)
                | Kind::Array { first: _, last: _ }
                | Kind::Alias(_) => {}
            }
        }
        let trees = tree_storage_data(
            containers,
            members,
            size_of::<String>() + size_of::<usize>(),
            align_of::<String>().max(align_of::<usize>()),
        )?;
        let total = sum(&[
            size_of::<Option<Self>>(),
            mul(texts.capacity(), size_of::<String>())?,
            mul(nodes.capacity(), size_of::<Node>())?,
            mul(edges.capacity(), size_of::<Edge>())?,
            mul(frames.capacity(), size_of::<Frame>())?,
            text,
            trees,
        ])?;
        if total > maximum {
            return Err(exhausted());
        }
        Ok(total)
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
