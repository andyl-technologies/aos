//! Preserves concrete native container geometry and typed reconstructed contents.

use super::super::current_shared::{CurrentShared17, shared_row17};
use super::*;
use serde::ser::SerializeSeq;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, size_of},
    rc::Rc,
    sync::Arc,
};

impl<T: Import17> Import17 for Option<T> {
    type Data = Option<T::Data>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            None => s.serialize_none(),
            Some(value) => s.serialize_some(&BorrowedImport17(value)),
        }
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        if input == b"null" {
            Ok(build.then_some(None))
        } else {
            T::read_current(input, l, build).map(|v| v.map(Some))
        }
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        if let Some(v) = self {
            v.observe_current(o)?;
        }
        Ok(())
    }
}

impl<T: Import17> Import17 for Vec<T> {
    type Data = Vec<T::Data>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut fields = s.serialize_tuple(2)?;
        serde::ser::SerializeTuple::serialize_element(&mut fields, &self.capacity())?;
        serde::ser::SerializeTuple::serialize_element(&mut fields, &ImportSequence17(self))?;
        serde::ser::SerializeTuple::end(fields)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let mut tuple = Fields::array(input)?;
        let explicit = l
            .read::<usize>(tuple.next_value()?.ok_or_else(invalid)?, true)?
            .ok_or_else(invalid)?;
        let raw = tuple.next_value()?.ok_or_else(invalid)?;
        tuple.finish()?;
        let capacity =
            l.row_aligned(MetadataRecordKind::Vector, size_of::<T>(), align_of::<T>())?;
        if explicit != capacity
            || capacity
                .checked_mul(size_of::<T>())
                .is_none_or(|n| n > l.limits.maximum_owned_backing_bytes)
        {
            return Err(invalid());
        }
        l.native17_target_vector_data::<T::Data>(capacity)?;
        let mut values = Vec::new();
        if build {
            values.try_reserve_exact(capacity).map_err(|_| invalid())?;
            if values.capacity() != capacity {
                return Err(invalid());
            }
        }
        let mut fields = Fields::array(raw)?;
        let mut length = 0usize;
        while let Some(raw) = fields.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > capacity {
                return Err(invalid());
            }
            if let Some(v) = T::read_current(raw, l, build)? {
                values.push(v);
            }
        }
        fields.finish()?;
        Ok(build.then_some(values))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.vector::<T>(self.capacity())?;
        for value in self {
            value.observe_current(o)?;
        }
        Ok(())
    }
}

struct ImportSequence17<'a, T: Import17>(&'a [T]);
impl<T: Import17> Serialize for ImportSequence17<'_, T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for v in self.0 {
            seq.serialize_element(&BorrowedImport17(v))?;
        }
        seq.end()
    }
}

impl<T: Import17, const N: usize> Import17 for [T; N] {
    type Data = [Option<T::Data>; N];
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ImportSequence17(self).serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let mut values: [Option<T::Data>; N] = std::array::from_fn(|_| None);
        for v in &mut values {
            *v = T::read_current(fields.next_value()?.ok_or_else(invalid)?, l, build)?;
        }
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            return Err(invalid());
        }
        Ok(Some(values))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        for v in self {
            v.observe_current(o)?;
        }
        Ok(())
    }
}

impl<A: Import17, B: Import17> Import17 for (A, B) {
    type Data = (A::Data, B::Data);
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&BorrowedImport17(&self.0), &BorrowedImport17(&self.1)).serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let mut f = Fields::array(input)?;
        let a = A::read_current(f.next_value()?.ok_or_else(invalid)?, l, build)?;
        let b = B::read_current(f.next_value()?.ok_or_else(invalid)?, l, build)?;
        f.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some((a.ok_or_else(invalid)?, b.ok_or_else(invalid)?)))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.0.observe_current(o)?;
        self.1.observe_current(o)
    }
}

impl<T: SharedImport17> Import17 for Rc<T> {
    type Data = CurrentShared17<T::Data>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_ref().write_current(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let start = l.rows.encoded_position();
        shared_row17(l, (size_of::<T>(), align_of::<T>()))?;
        let group = l.shared_begin(T::KIND)?;
        let value = T::read_current(input, l, build)?;
        let rows = l.rows.encoded_between(start)?;
        l.shared_finish(group, size_of::<T>(), input, rows)?;
        Ok(value.map(|payload| CurrentShared17 { group, payload }))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.shared_original(T::KIND, self.as_ref())?;
        self.as_ref().observe_current(o)
    }
}

impl Import17 for Arc<[crucible_node_format::ExtensionSelection]> {
    type Data = CurrentShared17<Vec<crucible_node_format::ExtensionSelection>>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ImportSequence17(self.as_ref()).serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        type E = crucible_node_format::ExtensionSelection;
        let start = l.rows.encoded_position();
        let bytes = l.row_aligned(MetadataRecordKind::Shared, 1, align_of::<E>())?;
        if bytes % size_of::<E>() != 0 {
            return Err(invalid());
        }
        let count = bytes / size_of::<E>();
        let group = l.shared_begin(MetadataSharedKind::HistoricalImportExtensions)?;
        l.native17_target_vector_data::<E>(count)?;
        let mut values = Vec::new();
        if build {
            values.try_reserve_exact(count).map_err(|_| invalid())?;
            if values.capacity() != count {
                return Err(invalid());
            }
        }
        let mut f = Fields::array(input)?;
        let mut length = 0usize;
        while let Some(raw) = f.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > count {
                return Err(invalid());
            }
            if let Some(v) = E::read_current(raw, l, build)? {
                values.push(v);
            }
        }
        f.finish()?;
        if length != count {
            return Err(invalid());
        }
        let rows = l.rows.encoded_between(start)?;
        l.shared_finish(group, bytes, input, rows)?;
        Ok(build.then_some(CurrentShared17 {
            group,
            payload: values,
        }))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.shared_original(
            MetadataSharedKind::HistoricalImportExtensions,
            self.as_ref(),
        )?;
        for v in self.as_ref() {
            v.observe_current(o)?;
        }
        Ok(())
    }
}

pub(super) trait ImportKey17: Import17 {
    fn compare_encoded(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering, ProviderError>;
}
impl<K: ImportKey17, V: Import17> Import17 for BTreeMap<K, V> {
    type Data = Vec<(K::Data, V::Data)>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.len()))?;
        for (k, v) in self {
            seq.serialize_element(&(BorrowedImport17(k), BorrowedImport17(v)))?;
        }
        seq.end()
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let count = l.row_aligned(
            MetadataRecordKind::Tree,
            size_of::<K>() + size_of::<V>(),
            align_of::<K>().max(align_of::<V>()),
        )?;
        if count > l.limits.maximum_tree_entries {
            return Err(invalid());
        }
        l.native17_target_vector_data::<(K::Data, V::Data)>(count)?;
        let mut values = Vec::new();
        if build {
            values.try_reserve_exact(count).map_err(|_| invalid())?;
            if values.capacity() != count {
                return Err(invalid());
            }
        }
        let mut fields = Fields::array(input)?;
        let mut length = 0usize;
        let mut previous = None;
        while let Some(raw) = fields.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > count {
                return Err(invalid());
            }
            let mut pair = Fields::array(raw)?;
            let key = pair.next_value()?.ok_or_else(invalid)?;
            let value = pair.next_value()?.ok_or_else(invalid)?;
            pair.finish()?;
            if let Some(prior) = previous
                && K::compare_encoded(prior, key)? != std::cmp::Ordering::Less
            {
                return Err(invalid());
            }
            previous = Some(key);
            let key = K::read_current(key, l, build)?;
            let value = V::read_current(value, l, build)?;
            if let (Some(k), Some(v)) = (key, value) {
                values.push((k, v));
            }
        }
        fields.finish()?;
        if length != count {
            return Err(invalid());
        }
        Ok(build.then_some(values))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.tree::<K, V>(self.len())?;
        for (k, v) in self {
            k.observe_current(o)?;
            v.observe_current(o)?;
        }
        Ok(())
    }
}

impl<T: ImportKey17> Import17 for BTreeSet<T> {
    type Data = Vec<T::Data>;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.len()))?;
        for v in self {
            seq.serialize_element(&BorrowedImport17(v))?;
        }
        seq.end()
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let count = l.row_aligned(MetadataRecordKind::Tree, size_of::<T>(), align_of::<T>())?;
        if count > l.limits.maximum_tree_entries {
            return Err(invalid());
        }
        l.native17_target_vector_data::<T::Data>(count)?;
        let mut values = Vec::new();
        if build {
            values.try_reserve_exact(count).map_err(|_| invalid())?;
            if values.capacity() != count {
                return Err(invalid());
            }
        }
        let mut f = Fields::array(input)?;
        let mut length = 0usize;
        let mut prior = None;
        while let Some(raw) = f.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > count {
                return Err(invalid());
            }
            if let Some(p) = prior
                && T::compare_encoded(p, raw)? != std::cmp::Ordering::Less
            {
                return Err(invalid());
            }
            prior = Some(raw);
            if let Some(v) = T::read_current(raw, l, build)? {
                values.push(v);
            }
        }
        f.finish()?;
        if length != count {
            return Err(invalid());
        }
        Ok(build.then_some(values))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.tree::<T, ()>(self.len())?;
        for v in self {
            v.observe_current(o)?;
        }
        Ok(())
    }
}
