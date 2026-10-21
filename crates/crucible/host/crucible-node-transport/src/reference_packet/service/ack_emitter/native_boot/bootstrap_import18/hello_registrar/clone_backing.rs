//! Counts fresh clones of the concrete immutable Hello installation fields.
//!
//! Counts use actual contents and lengths, so original spare capacities cannot
//! change correspondence between Source and a freshly decoded native launch.
//! This prices backing only. Actual clone/validation/registrar controls and
//! construction admission remain separate, and no Clone is executed here.
//!
//! Rust 1.98.1's alloc/src/string.rs delegates fresh Clone to Vec::clone;
//! alloc/src/vec/mod.rs delegates to slice::to_vec_in, whose concrete allocator
//! requests the original length. BTreeMap::clone preserves node populations,
//! bounded by the shared pinned node supplier. These facts do not cover
//! clone_from, custom allocators or a different JSON map/Number backend.

use crate::ProviderError;
use crate::handshake::{Limits, NegotiationPolicy, TrustedInstallation};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{
    ArtifactIdentity, ContentRef, HashRef, Id, ImplementationIdentity, SchemaRef, U64,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::mem::{align_of, needs_drop, size_of};

/// Tracks a bounded allocation-free walk over the original immutable fields.
pub(super) struct Walk {
    backing: usize,
    visited: usize,
    maximum: usize,
    tree_containers: usize,
    tree_entries: usize,
    tree_slot_bytes: usize,
    tree_alignment: usize,
    tree_backing: usize,
}

/// Names only the concrete fresh-clone field families below.
pub(super) trait CloneBacking {
    /// Adds the actual fresh clone's bounded allocating leaves and containers.
    ///
    /// # Errors
    /// Refuses unsupported layout, exhausted traversal or checked overflow.
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError>;

    /// Names controls of this allocation-free quote, excluding Clone itself.
    fn counter_scratch_data() -> usize;
}

impl Walk {
    /// Starts a separate walk without allocating a graph or capacity bank.
    ///
    /// # Errors
    /// Refuses zero bounds, a non-BTree JSON map or an owning Number layout.
    pub(super) fn new_data(maximum: usize) -> Result<Self, ProviderError> {
        // The pinned Number clone copies only its primitive enum. An owning
        // arbitrary-precision configuration requires its own backing supplier.
        if maximum == 0
            || crucible_node_format::canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_none()
            || needs_drop::<serde_json::Number>()
        {
            return Err(refused());
        }
        Ok(Self {
            backing: 0,
            visited: 0,
            maximum,
            tree_containers: 0,
            tree_entries: 0,
            tree_slot_bytes: 0,
            tree_alignment: 1,
            tree_backing: 0,
        })
    }

    /// Adds a concrete original field without cloning it.
    ///
    /// # Errors
    /// Refuses unsupported or excessive field populations and checked overflow.
    pub(super) fn observe_data<T: CloneBacking>(&mut self, value: &T) -> Result<(), ProviderError> {
        value.count_data(self)
    }

    /// Returns the quoted clone backing as ordinary unauthenticated DATA.
    pub(super) fn finish_data(self) -> usize {
        self.backing
    }

    /// Counts a fresh String from an original borrowed spelling.
    ///
    /// # Errors
    /// Refuses excessive traversal, backing demand or checked overflow.
    pub(super) fn text_data(&mut self, text: &str) -> Result<(), ProviderError> {
        self.text(text)
    }

    /// Counts the exact fresh Vec allocation before its element contents.
    ///
    /// # Errors
    /// Refuses excessive traversal, backing demand or checked overflow.
    pub(super) fn vector_population_data<T>(&mut self, length: usize) -> Result<(), ProviderError> {
        self.visit()?;
        self.add(length.checked_mul(size_of::<T>()).ok_or_else(refused)?)
    }

    /// Counts a concrete tree population in this owner's combined census.
    ///
    /// # Errors
    /// Refuses excessive traversal, backing demand or checked overflow.
    pub(super) fn tree_population_data<K, V>(
        &mut self,
        length: usize,
    ) -> Result<(), ProviderError> {
        self.visit()?;
        self.tree::<K, V>(length)
    }

    fn visit(&mut self) -> Result<(), ProviderError> {
        self.visited = self.visited.checked_add(1).ok_or_else(refused)?;
        if self.visited > self.maximum {
            return Err(refused());
        }
        Ok(())
    }

    fn add(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.backing = self.backing.checked_add(bytes).ok_or_else(refused)?;
        if self.backing > self.maximum {
            return Err(refused());
        }
        Ok(())
    }

    fn tree<K, V>(&mut self, entries: usize) -> Result<(), ProviderError> {
        self.tree_containers = self.tree_containers.checked_add(1).ok_or_else(refused)?;
        self.tree_entries = self.tree_entries.checked_add(entries).ok_or_else(refused)?;
        let slot_bytes = size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or_else(refused)?;
        self.tree_slot_bytes = self.tree_slot_bytes.max(slot_bytes);
        self.tree_alignment = self
            .tree_alignment
            .max(align_of::<K>())
            .max(align_of::<V>());
        // The retained owner uses one metadata census. Its actual tree families
        // share the maximum entry layout, including deliberately empty roots.
        let next = tree_storage_data(
            self.tree_containers,
            self.tree_entries,
            self.tree_slot_bytes,
            self.tree_alignment,
        )?;
        self.add(next.checked_sub(self.tree_backing).ok_or_else(refused)?)?;
        self.tree_backing = next;
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), ProviderError> {
        self.visit()?;
        // Fresh String/Id clones use the actual byte length, independent of
        // original spare capacity. Vec's fresh to_vec allocation is exact.
        self.add(text.len())
    }

    fn json(&mut self, value: &Value, depth: usize) -> Result<(), ProviderError> {
        self.visit()?;
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
            Value::String(text) => self.text(text),
            Value::Array(values) => {
                if depth >= 64 {
                    return Err(refused());
                }
                self.add(
                    values
                        .len()
                        .checked_mul(size_of::<Value>())
                        .ok_or_else(refused)?,
                )?;
                for value in values {
                    self.json(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                if depth >= 64 {
                    return Err(refused());
                }
                self.tree::<String, Value>(values.len())?;
                for (key, value) in values {
                    self.text(key)?;
                    self.json(value, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

impl CloneBacking for String {
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
        walk.text(self)
    }

    fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&str>()
            + size_of::<usize>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl CloneBacking for Id {
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
        walk.text(self.as_str())
    }

    fn counter_scratch_data() -> usize {
        size_of::<&Self>() + String::counter_scratch_data()
    }
}

macro_rules! scalar {
    ($($type:ty),+ $(,)?) => { $(
        impl CloneBacking for $type {
            fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
                walk.visit()
            }

            fn counter_scratch_data() -> usize {
                size_of::<&Self>() + size_of::<Result<(), ProviderError>>()
            }
        }
    )+ };
}

scalar!(U64, u16, [u8; 32]);

impl<T: CloneBacking + 'static> CloneBacking for Vec<T> {
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
        walk.visit()?;
        walk.add(self.len().checked_mul(size_of::<T>()).ok_or_else(refused)?)?;
        for value in self {
            value.count_data(walk)?;
        }
        Ok(())
    }

    fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<std::slice::Iter<'static, T>>()
            + size_of::<usize>() * 2
            + size_of::<Result<(), ProviderError>>()
            + T::counter_scratch_data()
    }
}

impl<T: CloneBacking + 'static> CloneBacking for BTreeMap<String, T> {
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
        walk.visit()?;
        walk.tree::<String, T>(self.len())?;
        for (key, value) in self {
            walk.text(key)?;
            value.count_data(walk)?;
        }
        Ok(())
    }

    fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<std::collections::btree_map::Iter<'static, String, T>>()
            + size_of::<usize>() * 5
            + size_of::<Result<(), ProviderError>>()
            + String::counter_scratch_data()
            + T::counter_scratch_data()
    }
}

impl CloneBacking for Value {
    fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
        walk.json(self, 0)
    }

    fn counter_scratch_data() -> usize {
        // One actual JSON match/iteration window per allowed container, plus
        // its terminal scalar. This is quote work, not a machine stack claim.
        65 * (size_of::<&Value>()
            + size_of::<&Map<String, Value>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<usize>() * 3
            + size_of::<Result<(), ProviderError>>())
    }
}

macro_rules! fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl CloneBacking for $type {
            fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
                walk.visit()?;
                $(self.$field.count_data(walk)?;)+
                Ok(())
            }

            fn counter_scratch_data() -> usize {
                size_of::<&Self>() + size_of::<Result<(), ProviderError>>()
                    $(+ field_counter(|value: &Self| &value.$field))+
            }
        }

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
}

fn field_counter<S, T: CloneBacking>(_: fn(&S) -> &T) -> usize {
    T::counter_scratch_data()
}

fields!(HashRef {
    algorithm,
    domain,
    digest
});
fields!(ContentRef {
    hash,
    length,
    media_type
});
fields!(SchemaRef {
    id,
    version,
    definition,
    extensions
});
fields!(ArtifactIdentity {
    id,
    role,
    content,
    extensions
});
fields!(ImplementationIdentity {
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions
});
fields!(Limits {
    frame_bytes,
    nesting,
    requests,
    journal_entries,
    blob_chunk_bytes
});
fields!(TrustedInstallation {
    session_id,
    incarnation_id,
    measured_implementation,
    launch_receipt,
    admission_token
});
fields!(NegotiationPolicy {
    supported_features,
    required_features,
    provider_limits,
    required_schemas,
    required_guarantees,
    envelope_extension_features
});

/// Names this walk's actual checked accumulation and result controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<Walk>()
        + size_of::<&mut Walk>()
        + size_of::<Result<Walk, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<usize>() * 4
        + size_of::<Option<[usize; 3]>>()
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original Hello installation clone backing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::PacketNative5SourceLaunch;
    use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    use serde_json::json;

    fn quote<T: CloneBacking>(value: &T) -> usize {
        let mut walk = Walk::new_data(268_435_456).unwrap();
        walk.observe_data(value).unwrap();
        walk.finish_data()
    }

    #[test]
    fn actual_implementation_clone_fits_without_pricing_original_spare_capacity() {
        for reactive in [false, true] {
            let selected = inert_bootstrap_fixtures::initial_selected_launch(reactive);
            let launch: PacketNative5SourceLaunch =
                serde_json::from_value(selected["launch"].clone()).unwrap();
            let mut original = launch.selection.provider.implementation.clone();
            let spelling = original.implementation_id.as_str();
            let mut spare = String::with_capacity(spelling.len() + 8192);
            spare.push_str(spelling);
            original.implementation_id = Id::new(spare).unwrap();
            original.extensions.insert(
                "ordinary/clone-data".into(),
                json!({
                    "$serde_json::private::RawValue": "[[[ordinary String]]]",
                    "nested": [false, null, 1, {"unicode":"\u{1f642}"}],
                }),
            );
            let projected = quote(&original);

            let cloned = original.clone();
            let mut observer = MetadataObserver::new();
            observer.observe(&cloned).unwrap();
            let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
            assert_eq!(projected, quote(&cloned));
            assert!(
                actual <= projected,
                "actual={actual}, projected={projected}"
            );
            assert!(original.implementation_id.as_str() == cloned.implementation_id.as_str());
        }
    }

    #[test]
    fn actual_combined_tree_layout_matches_the_retained_owner_census() {
        let keys = BTreeMap::from([("feature/key".to_owned(), Id::new("feature/1").unwrap())]);
        let extensions = BTreeMap::from([("data/key".to_owned(), json!({"child": [1,2,3]}))]);
        let mut walk = Walk::new_data(268_435_456).unwrap();
        walk.observe_data(&keys).unwrap();
        walk.observe_data(&extensions).unwrap();
        let projected = walk.finish_data();

        let keys = keys.clone();
        let extensions = extensions.clone();
        let mut observer = MetadataObserver::new();
        observer.observe(&keys).unwrap();
        observer.observe(&extensions).unwrap();
        assert!(requested_metadata_backing_storage_data(&observer.finish()).unwrap() <= projected);
    }

    #[test]
    fn clone_walk_refuses_unsupported_depth_and_short_independent_limits() {
        let mut value = Value::Null;
        for _ in 0..64 {
            value = Value::Array(vec![value]);
        }
        let projected = quote(&value);
        let mut short = Walk::new_data(projected - 1).unwrap();
        assert!(short.observe_data(&value).is_err());

        value = Value::Array(vec![value]);
        let mut bounded = Walk::new_data(268_435_456).unwrap();
        assert!(bounded.observe_data(&value).is_err());
        assert!(Walk::new_data(0).is_err());
    }
}
