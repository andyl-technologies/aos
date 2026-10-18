//! Reconstructs final typed historical fields after a complete borrowed pass.
//!
//! This reader has no serde deserializer or temporary whole-value DOM. The first
//! pass checks every field and capacity row; the second builds final String/Vec
//! owners exactly once. Dynamic Value fields use the independently bounded JSON
//! helper. Logical tree populations never imply allocator-node admission.

use super::json_value::{HistoricalJsonLimits, ValidatedHistoricalJson};
use crate::ProviderError;
use crate::retained_metadata::records::{MetadataRecordKind, MetadataRecordRows};
use crucible_node_contract::{Id, U64};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) trait HistoricalType: Sized {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError>;
}

pub(crate) mod native17_build;
mod native17_targets;
pub(crate) use native17_build::Native17Build;

pub(crate) struct Ledger<'a, 'scratch, 'input> {
    pub(crate) rows: MetadataRecordRows<'a>,
    pub(crate) aliases: Option<super::aliases::HistoricalAliasViews<'scratch, 'input>>,
    /// Uses the explicit17 vocabulary without changing old11 alias admission.
    pub(crate) settled_aliases: Option<
        crate::protocol_snapshot::restored_settled17::aliases::RestoredSettledNative17AliasViews<
            'scratch,
            'input,
        >,
    >,
    pub(crate) selected_groups: Option<
        &'scratch mut [Option<std::sync::Arc<[crucible_node_contract::ExtensionSelection]>>],
    >,
    pub(crate) limits: HistoricalJsonLimits,
    pub(crate) content_limits: Option<crate::client::compact_metadata8::CompactMetadata8Limits>,
    pub(crate) literal_bytes: usize,
    pub(crate) content_group_lookup_bytes: usize,
    pub(crate) selected_slice_staging_bytes: usize,
    pub(crate) maximum_literal_bytes: usize,
    native17_targets: Option<native17_targets::Native17Targets>,
    native17_target_groups: Option<&'scratch mut [bool]>,
    nodes: usize,
    depth: usize,
}

impl<'a, 'scratch, 'input> Ledger<'a, 'scratch, 'input> {
    pub(crate) fn new(rows: MetadataRecordRows<'a>, limits: HistoricalJsonLimits) -> Self {
        Self {
            rows,
            aliases: None,
            settled_aliases: None,
            selected_groups: None,
            limits,
            content_limits: None,
            literal_bytes: 0,
            content_group_lookup_bytes: 0,
            selected_slice_staging_bytes: 0,
            maximum_literal_bytes: 0,
            native17_targets: None,
            native17_target_groups: None,
            nodes: 0,
            depth: 0,
        }
    }

    pub(crate) fn read<T: HistoricalType>(
        &mut self,
        input: &[u8],
        build: bool,
    ) -> Result<Option<T>, ProviderError> {
        self.validate_alias_backend()?;
        self.nodes = self.nodes.checked_add(1).ok_or_else(invalid)?;
        if self.nodes > self.limits.maximum_nodes
            || input.len() > self.limits.maximum_input_bytes
            || self.depth >= self.limits.maximum_depth
        {
            return Err(invalid());
        }
        self.depth += 1;
        let result = T::read(input, self, build);
        self.depth -= 1;
        if result.is_err() {
            self.fail_native17_targets_data();
        }
        result
    }

    pub(crate) fn shared(
        &mut self,
        kind: crate::retained_metadata::aliases::MetadataSharedKind,
        layout: usize,
        view: &[u8],
        capacity_rows: &[u8],
    ) -> Result<usize, ProviderError> {
        match (&mut self.aliases, &mut self.settled_aliases) {
            (Some(aliases), None) => aliases.observe(kind, layout, view, capacity_rows),
            (None, Some(aliases)) => aliases.observe(kind, layout, view, capacity_rows),
            _ => Err(invalid()),
        }
    }

    /// Consumes the shared row before walking children in source order.
    ///
    /// # Errors
    /// Refuses absent or mixed backends, wrong kinds, cycles or exhausted rows.
    pub(crate) fn shared_begin(
        &mut self,
        kind: crate::retained_metadata::aliases::MetadataSharedKind,
    ) -> Result<usize, ProviderError> {
        match (&mut self.aliases, &mut self.settled_aliases) {
            (Some(aliases), None) => aliases.begin(kind),
            (None, Some(aliases)) => aliases.begin(kind),
            _ => Err(invalid()),
        }
    }

    /// Conjoins the complete parent view and capacity rows after its children.
    ///
    /// # Errors
    /// Refuses absent or mixed backends and inconsistent or unfinished groups.
    pub(crate) fn shared_finish(
        &mut self,
        group: usize,
        layout: usize,
        view: &[u8],
        capacity_rows: &[u8],
    ) -> Result<(), ProviderError> {
        match (&mut self.aliases, &mut self.settled_aliases) {
            (Some(aliases), None) => aliases.finish_group(group, layout, view, capacity_rows),
            (None, Some(aliases)) => aliases.finish_group(group, layout, view, capacity_rows),
            _ => Err(invalid()),
        }
    }

    /// Conjoins compact-content first groups with the enclosing shared roster.
    ///
    /// # Errors
    /// Refuses absent or mixed backends and inconsistent content or alias edges.
    pub(crate) fn shared_content(
        &mut self,
        edge: crate::client::compact_cursor::ContentGroupEdge,
        layout: usize,
        digest: &[u8],
        capacity_rows: &[u8],
    ) -> Result<usize, ProviderError> {
        match (&mut self.aliases, &mut self.settled_aliases) {
            (Some(aliases), None) => aliases.observe_content(edge, layout, digest, capacity_rows),
            (None, Some(aliases)) => aliases.observe_content(edge, layout, digest, capacity_rows),
            _ => Err(invalid()),
        }
    }

    /// Consumes an explicit17 role edge to an already completed full group.
    ///
    /// The child separately consumes the exact aligned Shared capacity record.
    /// Old11 archives have no role-only references and are refused here.
    ///
    /// # Errors
    /// Refuses other backends and undefined, unfinished or mismatching groups.
    pub(crate) fn shared_reference(
        &mut self,
        kind: crate::retained_metadata::aliases::MetadataSharedKind,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        match (&mut self.aliases, &mut self.settled_aliases) {
            (None, Some(aliases)) => aliases.reference(kind, layout),
            _ => Err(invalid()),
        }
    }

    /// Requires exactly one backend and a completely consumed alias pass.
    ///
    /// # Errors
    /// Refuses absent or mixed backends and failed, short or unfinished passes.
    /// Consumes an explicit17 role-only edge to the currently parsed Boot.
    ///
    /// The caller consumes its actual Shared capacity row separately and
    /// supplies the exact group returned by this enclosing Boot's begin. Old11
    /// alias backends cannot use this rule; no native Rc or permission is made.
    pub(crate) fn shared_native_boot_parent_reference(
        &mut self,
        expected_group: usize,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        self.validate_alias_backend()?;
        if self.aliases.is_some() {
            return Err(invalid());
        }
        self.settled_aliases
            .as_mut()
            .ok_or_else(invalid)?
            .native_boot_parent_reference(expected_group, layout)
    }

    pub(crate) fn finish_aliases(&mut self) -> Result<(), ProviderError> {
        self.validate_alias_backend()?;
        match (self.aliases.take(), self.settled_aliases.take()) {
            (Some(aliases), None) => aliases.finish(),
            (None, Some(aliases)) => aliases.finish(),
            _ => Err(invalid()),
        }
    }

    fn validate_alias_backend(&self) -> Result<(), ProviderError> {
        // Old callers assign aliases directly. Refuse a mixed backend before
        // consuming typed children instead of silently preferring either era.
        if self.aliases.is_some() && self.settled_aliases.is_some() {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn row_aligned(
        &mut self,
        kind: MetadataRecordKind,
        layout: usize,
        alignment: usize,
    ) -> Result<usize, ProviderError> {
        let row = self.rows.next().ok_or_else(invalid)??;
        if row.kind != kind || row.element_bytes != layout || row.alignment != alignment {
            return Err(invalid());
        }
        Ok(row.extent)
    }

    pub(crate) fn row(
        &mut self,
        kind: MetadataRecordKind,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        let row = self.rows.next().ok_or_else(invalid)??;
        if row.kind != kind || row.element_bytes != layout {
            return Err(invalid());
        }
        Ok(row.extent)
    }
}

impl HistoricalType for String {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
        if input.first() != Some(&b'"') {
            return Err(invalid());
        }
        ledger.native17_target_json_data(&plan)?;
        ledger.rows = plan.remaining_records();
        if !build {
            return Ok(None);
        }
        let Value::String(value) = plan.reconstruct()? else {
            return Err(invalid());
        };
        Ok(Some(value))
    }
}

impl HistoricalType for Id {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let text = plain_string(input)?;
        if text.is_empty()
            || text.len() > 128
            || !text.as_bytes()[0].is_ascii_alphanumeric()
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(invalid());
        }
        let value = String::read(input, ledger, build)?;
        value.map(Id::new).transpose().map_err(ProviderError::from)
    }
}

impl HistoricalType for U64 {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let value = unsigned(plain_string(input)?.as_bytes())?;
        Ok(build.then_some(U64::new(value)))
    }
}

macro_rules! unsigned_integer {
    ($($type:ty),+ $(,)?) => { $(impl HistoricalType for $type {
        fn read(input: &[u8], _: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
            let value = <$type>::try_from(unsigned(input)?).map_err(|_| invalid())?;
            Ok(build.then_some(value))
        }
    })+ };
}
unsigned_integer!(u8, u16, u32, u64);

impl HistoricalType for usize {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let value = usize::try_from(unsigned(input)?).map_err(|_| invalid())?;
        Ok(build.then_some(value))
    }
}

impl HistoricalType for bool {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let value = match input {
            b"true" => true,
            b"false" => false,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(value))
    }
}

impl<T: HistoricalType> HistoricalType for Option<T> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        if input == b"null" {
            return Ok(build.then_some(None));
        }
        Ok(ledger.read::<T>(input, build)?.map(Some))
    }
}

impl<T: HistoricalType> HistoricalType for Vec<T> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            std::mem::size_of::<T>(),
            std::mem::align_of::<T>(),
        )?;
        ledger.native17_target_vector_data::<T>(capacity)?;
        let mut cursor = Fields::array(input)?;
        let mut result = Vec::new();
        if build {
            result.try_reserve_exact(capacity).map_err(|_| credit())?;
            if result.capacity() != capacity {
                return Err(credit());
            }
        }
        let mut count = 0usize;
        while let Some(field) = cursor.next()? {
            count = count.checked_add(1).ok_or_else(invalid)?;
            if count > capacity {
                return Err(invalid());
            }
            if let Some(value) = ledger.read::<T>(field, build)? {
                result.push(value);
            }
        }
        Ok(build.then_some(result))
    }
}

impl HistoricalType for Map<String, Value> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
        if input.first() != Some(&b'{') {
            return Err(invalid());
        }
        ledger.native17_target_json_data(&plan)?;
        ledger.rows = plan.remaining_records();
        if !build {
            return Ok(None);
        }
        let Value::Object(value) = plan.reconstruct()? else {
            return Err(invalid());
        };
        Ok(Some(value))
    }
}

impl HistoricalType for BTreeMap<String, Value> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
        if input.first() != Some(&b'{') {
            return Err(invalid());
        }
        ledger.native17_target_json_data(&plan)?;
        ledger.rows = plan.remaining_records();
        if !build {
            return Ok(None);
        }
        Ok(Some(plan.reconstruct_extensions()?))
    }
}

impl HistoricalType for Value {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
        ledger.native17_target_json_data(&plan)?;
        ledger.rows = plan.remaining_records();
        if build {
            Ok(Some(plan.reconstruct()?))
        } else {
            Ok(None)
        }
    }
}

impl HistoricalType for BTreeMap<String, Id> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let entries = ledger.row_aligned(
            MetadataRecordKind::Tree,
            std::mem::size_of::<String>() + std::mem::size_of::<Id>(),
            std::mem::align_of::<String>().max(std::mem::align_of::<Id>()),
        )?;
        ledger.native17_target_tree_data::<String, Id>(entries)?;
        let mut fields = Fields::object(input)?;
        let mut result = BTreeMap::new();
        let mut count = 0usize;
        let mut previous = None;
        while let Some((key, value)) = fields.pair()? {
            let text = plain_string(key)?;
            if previous.is_some_and(|prior| prior >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            let key = ledger.read::<String>(key, build)?;
            let value = ledger.read::<Id>(value, build)?;
            count += 1;
            if count > entries {
                return Err(invalid());
            }
            if let (Some(key), Some(value)) = (key, value) {
                result.insert(key, value);
            }
        }
        if count != entries {
            return Err(invalid());
        }
        Ok(build.then_some(result))
    }
}

impl<V: HistoricalType> HistoricalType for BTreeMap<Id, V> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let entries = ledger.row_aligned(
            MetadataRecordKind::Tree,
            std::mem::size_of::<Id>() + std::mem::size_of::<V>(),
            std::mem::align_of::<Id>().max(std::mem::align_of::<V>()),
        )?;
        ledger.native17_target_tree_data::<Id, V>(entries)?;
        let mut fields = Fields::object(input)?;
        let mut result = BTreeMap::new();
        let mut count = 0usize;
        let mut previous = None;
        while let Some((key, value)) = fields.pair()? {
            let text = plain_string(key)?;
            if previous.is_some_and(|prior| prior >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            let key = ledger.read::<Id>(key, build)?;
            let value = ledger.read::<V>(value, build)?;
            count += 1;
            if count > entries {
                return Err(invalid());
            }
            if let (Some(key), Some(value)) = (key, value) {
                result.insert(key, value);
            }
        }
        if count != entries {
            return Err(invalid());
        }
        Ok(build.then_some(result))
    }
}

impl HistoricalType for BTreeSet<String> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let entries = ledger.row_aligned(
            MetadataRecordKind::Tree,
            std::mem::size_of::<String>(),
            std::mem::align_of::<String>(),
        )?;
        ledger.native17_target_tree_data::<String, ()>(entries)?;
        let mut fields = Fields::array(input)?;
        let mut result = BTreeSet::new();
        let mut count = 0usize;
        let mut previous = None;
        while let Some(field) = fields.next()? {
            // Selected source extension identifiers are unescaped bounded ASCII.
            let text = plain_string(field)?;
            if previous.is_some_and(|prior| prior >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            let value = ledger.read::<String>(field, build)?;
            count += 1;
            if count > entries {
                return Err(invalid());
            }
            if let Some(value) = value {
                result.insert(value);
            }
        }
        if count != entries {
            return Err(invalid());
        }
        Ok(build.then_some(result))
    }
}
impl HistoricalType for BTreeSet<Id> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let entries = ledger.row_aligned(
            MetadataRecordKind::Tree,
            std::mem::size_of::<Id>(),
            std::mem::align_of::<Id>(),
        )?;
        ledger.native17_target_tree_data::<Id, ()>(entries)?;
        let mut fields = Fields::array(input)?;
        let mut result = BTreeSet::new();
        let mut count = 0usize;
        let mut previous = None;
        while let Some(field) = fields.next()? {
            // Selected source extension identifiers are unescaped bounded ASCII.
            let text = plain_string(field)?;
            if previous.is_some_and(|prior| prior >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            let value = ledger.read::<Id>(field, build)?;
            count += 1;
            if count > entries {
                return Err(invalid());
            }
            if let Some(value) = value {
                result.insert(value);
            }
        }
        if count != entries {
            return Err(invalid());
        }
        Ok(build.then_some(result))
    }
}

type BorrowedFieldPair<'a> = (&'a [u8], &'a [u8]);

pub(crate) struct Fields<'a> {
    input: &'a [u8],
    position: usize,
    closing: u8,
    first: bool,
}

impl<'a> Fields<'a> {
    pub(crate) fn array(input: &'a [u8]) -> Result<Self, ProviderError> {
        Self::new(input, b'[', b']')
    }
    pub(crate) fn object(input: &'a [u8]) -> Result<Self, ProviderError> {
        Self::new(input, b'{', b'}')
    }

    fn new(input: &'a [u8], opening: u8, closing: u8) -> Result<Self, ProviderError> {
        if input.first() != Some(&opening) || input.last() != Some(&closing) {
            return Err(invalid());
        }
        Ok(Self {
            input,
            position: 1,
            closing,
            first: true,
        })
    }

    pub(crate) fn next(&mut self) -> Result<Option<&'a [u8]>, ProviderError> {
        if self.input.get(self.position) == Some(&self.closing) {
            if self.position + 1 != self.input.len() {
                return Err(invalid());
            }
            return Ok(None);
        }
        if !self.first {
            self.require(b',')?;
        }
        self.first = false;
        Ok(Some(self.span()?))
    }

    pub(crate) fn pair(&mut self) -> Result<Option<BorrowedFieldPair<'a>>, ProviderError> {
        let Some(key) = self.next()? else {
            return Ok(None);
        };
        self.require(b':')?;
        Ok(Some((key, self.span()?)))
    }

    pub(crate) fn named(&mut self, name: &str) -> Result<&'a [u8], ProviderError> {
        let (key, value) = self.pair()?.ok_or_else(invalid)?;
        if plain_string(key)? != name {
            return Err(invalid());
        }
        Ok(value)
    }

    pub(crate) fn finish(&mut self) -> Result<(), ProviderError> {
        if self.next()?.is_some() {
            return Err(invalid());
        }
        Ok(())
    }

    fn require(&mut self, byte: u8) -> Result<(), ProviderError> {
        if self.input.get(self.position) != Some(&byte) {
            return Err(invalid());
        }
        self.position += 1;
        Ok(())
    }

    fn span(&mut self) -> Result<&'a [u8], ProviderError> {
        let start = self.position;
        let mut stack = [0u8; 128];
        let mut depth = 0usize;
        let mut string = false;
        let mut escaped = false;
        while let Some(byte) = self.input.get(self.position).copied() {
            if !string && depth == 0 && (byte == b',' || byte == b':' || byte == self.closing) {
                break;
            }
            self.position += 1;
            if string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
                continue;
            }
            match byte {
                b'"' => string = true,
                b'[' | b'{' => {
                    if depth == stack.len() {
                        return Err(invalid());
                    }
                    stack[depth] = if byte == b'[' { b']' } else { b'}' };
                    depth += 1;
                }
                b']' | b'}' => {
                    if depth == 0 || stack[depth - 1] != byte {
                        return Err(invalid());
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if self.position == start || string || depth != 0 {
            return Err(invalid());
        }
        Ok(&self.input[start..self.position])
    }
}

pub(crate) fn plain_string(input: &[u8]) -> Result<&str, ProviderError> {
    if input.len() < 2 || input.first() != Some(&b'"') || input.last() != Some(&b'"') {
        return Err(invalid());
    }
    let text = &input[1..input.len() - 1];
    if text
        .iter()
        .any(|byte| *byte < 32 || matches!(*byte, b'"' | b'\\'))
    {
        return Err(invalid());
    }
    std::str::from_utf8(text).map_err(|_| invalid())
}

pub(crate) fn unsigned(input: &[u8]) -> Result<u64, ProviderError> {
    if input.is_empty() || (input.len() > 1 && input[0] == b'0') {
        return Err(invalid());
    }
    let mut value = 0u64;
    for digit in input {
        if !digit.is_ascii_digit() {
            return Err(invalid());
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or_else(invalid)?;
    }
    Ok(value)
}

pub(crate) fn invalid() -> ProviderError {
    ProviderError::Frame("typed historical field grammar or roster")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("typed historical owner capacity")
}

macro_rules! historical_struct {
    ($type:ty { $($field:ident : $child:ty),+ $(,)? }) => {
        impl HistoricalType for $type {
            fn read(input: &[u8], ledger: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let mut fields = $crate::protocol_snapshot::owned11::typed::Fields::object(input)?;
                $(let $field = ledger.read::<$child>(fields.named(stringify!($field))?, build)?;)+
                fields.finish()?;
                if !build { return Ok(None); }
                Ok(Some(Self { $($field: $field.ok_or_else(invalid)?),+ }))
            }
        }
    };
}
pub(crate) use historical_struct;

// Only the actual closed Position/Phase serializer is admitted by this leaf.
#[path = "typed/position.rs"]
mod position;

#[path = "typed/bytes.rs"]
mod bytes;
pub(crate) use bytes::historical_bytes_counter_scratch_data;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual DATA backing identity fixture observations"
)]
#[path = "typed/alias_dispatch.rs"]
mod alias_dispatch;
