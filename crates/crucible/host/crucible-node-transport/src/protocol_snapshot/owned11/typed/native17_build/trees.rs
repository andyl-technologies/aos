//! Keeps completed map entries and each pending key/value attempt on failure.

use super::Native17Build;
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, credit, invalid, plain_string,
};
use crate::retained_metadata::{MetadataObserver, records::MetadataRecordKind};
use crucible_node_format::Id;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::{align_of, size_of};

struct PairAttempt<K: Native17Build, V: Native17Build> {
    key: K::Attempt,
    value: V::Attempt,
    key_output: Option<K>,
    value_output: Option<V>,
}

impl<K: Native17Build, V: Native17Build> Default for PairAttempt<K, V> {
    fn default() -> Self {
        Self {
            key: Default::default(),
            value: Default::default(),
            key_output: None,
            value_output: None,
        }
    }
}

/// Retains independent entry-builder backing beside the final tree nodes.
pub(crate) struct Native17TreeAttempt<K: Native17Build, V: Native17Build> {
    entries: Vec<PairAttempt<K, V>>,
    output: BTreeMap<K, V>,
    started: bool,
    failed: bool,
    completed: bool,
    output_moved: bool,
}

impl<K: Native17Build, V: Native17Build> Default for Native17TreeAttempt<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            output: BTreeMap::new(),
            started: false,
            failed: false,
            completed: false,
            output_moved: false,
        }
    }
}

fn row_data<K, V>(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    ledger.row_aligned(
        MetadataRecordKind::Tree,
        size_of::<K>() + size_of::<V>(),
        align_of::<K>().max(align_of::<V>()),
    )
}

fn preflight_map_data<K: Native17Build + Ord, V: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    let count = row_data::<K, V>(ledger)?;
    ledger.native17_target_tree_data::<K, V>(count)?;
    ledger.native17_target_vector_data::<PairAttempt<K, V>>(count)?;
    let mut fields = Fields::object(input)?;
    let mut previous = None;
    let mut consumed = 0usize;
    while let Some((key, value)) = fields.pair()? {
        let text = plain_string(key)?;
        if previous.is_some_and(|previous| previous >= text) {
            return Err(invalid());
        }
        previous = Some(text);
        consumed = consumed.checked_add(1).ok_or_else(credit)?;
        if consumed > count {
            return Err(invalid());
        }
        K::preflight_data(key, ledger)?;
        V::preflight_data(value, ledger)?;
    }
    if consumed != count {
        return Err(invalid());
    }
    Ok(())
}

fn read_map_into_data<K: Native17Build + Ord, V: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut Native17TreeAttempt<K, V>,
) -> Result<(), ProviderError> {
    let repeated = std::mem::replace(&mut attempt.started, true);
    attempt.failed = true;
    if repeated {
        return Err(invalid());
    }
    let count = row_data::<K, V>(ledger)?;
    ledger.native17_target_tree_data::<K, V>(count)?;
    ledger.native17_target_vector_data::<PairAttempt<K, V>>(count)?;
    attempt
        .entries
        .try_reserve_exact(count)
        .map_err(|_| credit())?;
    if attempt.entries.capacity() != count {
        return Err(credit());
    }
    let mut fields = Fields::object(input)?;
    let mut previous = None;
    while let Some((key, value)) = fields.pair()? {
        let text = plain_string(key)?;
        if previous.is_some_and(|previous| previous >= text) || attempt.entries.len() == count {
            return Err(invalid());
        }
        previous = Some(text);
        attempt.entries.push(Default::default());
        let entry = attempt.entries.last_mut().ok_or_else(invalid)?;
        K::read_into_data(key, ledger, &mut entry.key)?;
        entry.key_output = K::take_output_data(&mut entry.key);
        if entry.key_output.is_none() {
            return Err(invalid());
        }
        V::read_into_data(value, ledger, &mut entry.value)?;
        entry.value_output = V::take_output_data(&mut entry.value);
        let key = entry.key_output.as_ref().ok_or_else(invalid)?;
        if attempt.output.contains_key(key) || entry.value_output.is_none() {
            return Err(invalid());
        }
        match (entry.key_output.take(), entry.value_output.take()) {
            (Some(key), Some(value)) => {
                attempt.output.insert(key, value);
            }
            (key, value) => {
                entry.key_output = key;
                entry.value_output = value;
                return Err(invalid());
            }
        }
    }
    if attempt.entries.len() != count {
        return Err(invalid());
    }
    attempt.completed = true;
    attempt.failed = false;
    Ok(())
}

fn observe_map_output_data<K: Native17Build, V: Native17Build>(
    output: &BTreeMap<K, V>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.tree::<K, V>(output.len())?;
    for (key, value) in output {
        K::observe_output_data(key, observer)?;
        V::observe_output_data(value, observer)?;
    }
    Ok(())
}

fn observe_map_attempt_data<K: Native17Build, V: Native17Build>(
    attempt: &Native17TreeAttempt<K, V>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    if !attempt.started {
        return Ok(());
    }
    observer.vector::<PairAttempt<K, V>>(attempt.entries.capacity())?;
    for entry in &attempt.entries {
        K::observe_attempt_data(&entry.key, observer)?;
        V::observe_attempt_data(&entry.value, observer)?;
        if let Some(key) = &entry.key_output {
            K::observe_output_data(key, observer)?;
        }
        if let Some(value) = &entry.value_output {
            V::observe_output_data(value, observer)?;
        }
    }
    if !attempt.output_moved {
        observe_map_output_data(&attempt.output, observer)?;
    }
    Ok(())
}

macro_rules! map_owner {
    ([$($generic:tt)*]; $key:ty, $value:ty) => {
        impl $($generic)* Native17Build for BTreeMap<$key, $value> {
            type Attempt = Native17TreeAttempt<$key, $value>;

            fn preflight_data(
                input: &[u8], ledger: &mut Ledger<'_, '_, '_>
            ) -> Result<(), ProviderError> {
                preflight_map_data::<$key, $value>(input, ledger)
            }

            fn read_into_data(
                input: &[u8], ledger: &mut Ledger<'_, '_, '_>, attempt: &mut Self::Attempt
            ) -> Result<(), ProviderError> {
                read_map_into_data(input, ledger, attempt)
            }

            fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
                if attempt.failed || !attempt.completed {
                    None
                } else {
                    Some(&attempt.output)
                }
            }

            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
                if attempt.failed || !attempt.completed {
                    return None;
                }

                attempt.completed = false;
                attempt.output_moved = true;
                Some(std::mem::take(&mut attempt.output))
            }

            fn observe_attempt_data(
                attempt: &Self::Attempt, observer: &mut MetadataObserver<'_>
            ) -> Result<(), ProviderError> {
                observe_map_attempt_data(attempt, observer)
            }

            fn observe_output_data(
                output: &Self, observer: &mut MetadataObserver<'_>
            ) -> Result<(), ProviderError> {
                observe_map_output_data(output, observer)
            }
        }
    };
}

map_owner!([<V: Native17Build>]; Id, V);
map_owner!([]; String, Id);

/// Retains each set element's child attempt independently from final tree nodes.
pub(crate) struct Native17SetAttempt<T: Native17Build> {
    children: Vec<T::Attempt>,
    output: BTreeSet<T>,
    started: bool,
    failed: bool,
    completed: bool,
    output_moved: bool,
}

impl<T: Native17Build> Default for Native17SetAttempt<T> {
    fn default() -> Self {
        Self {
            children: Vec::new(),
            output: BTreeSet::new(),
            started: false,
            failed: false,
            completed: false,
            output_moved: false,
        }
    }
}

impl<T: Native17Build + Ord> Native17Build for BTreeSet<T>
where
    BTreeSet<T>: HistoricalType,
{
    type Attempt = Native17SetAttempt<T>;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let count = row_data::<T, ()>(ledger)?;
        ledger.native17_target_tree_data::<T, ()>(count)?;
        ledger.native17_target_vector_data::<T::Attempt>(count)?;
        let mut fields = Fields::array(input)?;
        let mut previous = None;
        let mut consumed = 0usize;
        while let Some(field) = fields.next()? {
            let text = plain_string(field)?;
            if previous.is_some_and(|previous| previous >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            consumed = consumed.checked_add(1).ok_or_else(credit)?;
            if consumed > count {
                return Err(invalid());
            }
            T::preflight_data(field, ledger)?;
        }
        if consumed != count {
            return Err(invalid());
        }
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        if repeated {
            return Err(invalid());
        }
        let count = row_data::<T, ()>(ledger)?;
        ledger.native17_target_tree_data::<T, ()>(count)?;
        ledger.native17_target_vector_data::<T::Attempt>(count)?;
        attempt
            .children
            .try_reserve_exact(count)
            .map_err(|_| credit())?;
        if size_of::<T::Attempt>() != 0 && attempt.children.capacity() != count {
            return Err(credit());
        }
        let mut fields = Fields::array(input)?;
        let mut previous = None;
        while let Some(field) = fields.next()? {
            let text = plain_string(field)?;
            if previous.is_some_and(|previous| previous >= text) || attempt.children.len() == count
            {
                return Err(invalid());
            }
            previous = Some(text);
            attempt.children.push(Default::default());
            let child = attempt.children.last_mut().ok_or_else(invalid)?;
            T::read_into_data(field, ledger, child)?;
            let value = T::output_data(child).ok_or_else(invalid)?;
            if attempt.output.contains(value) {
                return Err(invalid());
            }
            if let Some(value) = T::take_output_data(child) {
                attempt.output.insert(value);
            } else {
                return Err(invalid());
            }
        }
        if attempt.children.len() != count {
            return Err(invalid());
        }
        attempt.completed = true;
        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        if attempt.failed || !attempt.completed {
            None
        } else {
            Some(&attempt.output)
        }
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed || !attempt.completed {
            return None;
        }
        attempt.completed = false;
        attempt.output_moved = true;
        Some(std::mem::take(&mut attempt.output))
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if !attempt.started {
            return Ok(());
        }
        observer.vector::<T::Attempt>(attempt.children.capacity())?;
        for child in &attempt.children {
            T::observe_attempt_data(child, observer)?;
        }
        if !attempt.output_moved {
            Self::observe_output_data(&attempt.output, observer)?;
        }
        Ok(())
    }

    fn observe_output_data(
        output: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.tree::<T, ()>(output.len())?;
        for value in output {
            T::observe_output_data(value, observer)?;
        }
        Ok(())
    }
}
