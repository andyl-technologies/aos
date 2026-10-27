//! Prices the concrete initial Hello result's fresh owned field population.
//!
//! Provider manifests include their complete profile and facet declarations.
//! The existing pinned String, Vec, tree and JSON clone suppliers cover their
//! allocating leaves. This supplier constructs no response or random challenge;
//! its enclosing constructor must separately fund entropy, guards and census.

use super::clone_backing::{CloneBacking, Walk};
use super::clone_controls::{self, CloneControls};
use crate::ProviderError;
use crate::envelope::Nullable;
use crate::handshake::{HelloResult, Limits, ResumedOperation};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, native_import18_hello_declaration_data,
};
use crucible_node_format::{FacetSelection, Id, NodeManifest, ProviderManifest};
use std::mem::size_of;

macro_rules! result_fields {
    ($($field:ident),+ $(,)?) => {
        type CloneFields = [[usize; 2]; 1 $(+ { let _ = stringify!($field); 1 })+];

        const _: fn(&HelloResult) = |value| {
            let HelloResult { $($field: _,)+ } = value;
        };
    };
}

result_fields!(
    version,
    session_id,
    incarnation_id,
    controller_nonce,
    provider_nonce,
    selected_features,
    limits,
    resume_token,
    provider_identity,
    resumed_operations,
);

macro_rules! manifest_fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl CloneBacking for $type {
            fn count_data(&self, walk: &mut Walk) -> Result<(), ProviderError> {
                $(walk.observe_data(&self.$field)?;)+
                Ok(())
            }

            fn counter_scratch_data() -> usize {
                const FIELDS: usize = 0 $(+ { let _ = stringify!($field); 1 })+;
                let children: [usize; FIELDS] = [
                    $(field_backing_counter(|value: &Self| &value.$field),)+
                ];
                // Field walks return before the next sibling starts. Their
                // recursive controls reuse a window; quote-array and iterator
                // controls remain physical dependencies of this calculation.
                size_of::<&Self>()
                    + size_of::<Result<(), ProviderError>>()
                    + size_of::<[usize; FIELDS]>()
                    + size_of::<std::array::IntoIter<usize, FIELDS>>()
                    + children.into_iter().fold(0, usize::max)
            }
        }

        impl CloneControls for $type {
            fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
                const ROWS: usize = 1 $(+ { let _ = stringify!($field); 1 })+;
                let rows: [[usize; 2]; ROWS] = [
                    [size_of::<Self>(), size_of::<&Self>()],
                    $(field_controls(|value: &Self| &value.$field)?,)+
                ];
                clone_controls::combine(&rows)
            }

            fn quote_counter_scratch_data() -> usize {
                const ROWS: usize = 1 $(+ { let _ = stringify!($field); 1 })+;
                const FIELDS: usize = ROWS - 1;
                let children: [usize; FIELDS] = [
                    $(field_quote_counter(|value: &Self| &value.$field),)+
                ];
                size_of::<[[usize; 2]; ROWS]>()
                    + composition_counter_scratch_data()
                    + size_of::<[usize; FIELDS]>()
                    + size_of::<std::array::IntoIter<usize, FIELDS>>()
                    + children.into_iter().fold(0, usize::max)
            }
        }

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
}

manifest_fields!(FacetSelection {
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions,
});

manifest_fields!(NodeManifest {
    schema_version,
    profile_id,
    roles,
    configuration_schema,
    allowed_combinations_ref,
    port_templates_ref,
    state_formats,
    operation_facets,
    extensions,
});

manifest_fields!(ProviderManifest {
    schema_version,
    provider_id,
    implementation,
    protocol_versions,
    supported_profiles,
    extensions_supported,
    qualification_refs,
    extensions,
});

/// Quotes every fresh owned initial result field without constructing a result.
///
/// Both challenges have the initial profile's checked 32-byte length. The
/// controller challenge is cloned from its actual typed request; a separately
/// acquired provider challenge is copied from the retained fixed array. Empty
/// resumption fields own no backing. Complete SDK validation remains separate.
///
/// # Errors
/// Refuses a foreign native declaration, missing sole binding, unsupported
/// clone layouts, exhausted bounded traversal or checked demand overflow.
pub(in super::super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut walk = Walk::new_data(maximum)?;
    walk.text_data("CNP/1")?;
    walk.observe_data(&binding.authority.session_id)?;
    walk.observe_data(&binding.authority.incarnation_id)?;
    walk.vector_population_data::<u8>(32)?;
    walk.vector_population_data::<u8>(32)?;
    walk.vector_population_data::<Id>(declaration.feature_count_data())?;
    for feature in declaration.features_data().iter().flatten() {
        walk.text_data(feature)?;
    }
    walk.observe_data(&launch.selection.provider)?;

    let fields: CloneFields = [
        [size_of::<HelloResult>(), size_of::<&HelloResult>()],
        String::fresh_controls_data()?,
        Id::fresh_controls_data()?,
        Id::fresh_controls_data()?,
        clone_controls::vector_data::<u8>()?,
        clone_controls::vector_data::<u8>()?,
        Vec::<Id>::fresh_controls_data()?,
        [size_of::<Limits>(), 0],
        [size_of::<Nullable<crucible_node_format::Bytes>>(), 0],
        ProviderManifest::fresh_controls_data()?,
        [size_of::<Vec<ResumedOperation>>(), 0],
    ];
    walk.finish_clone_data(clone_controls::combine(&fields)?)
}

/// Names the actual manifest walk, clone compositions and fixed quote controls.
pub(in super::super) fn counter_scratch_data() -> usize {
    ProviderManifest::counter_scratch_data()
        + ProviderManifest::quote_counter_scratch_data()
        + PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + super::clone_backing::counter_scratch_data()
        + clone_controls::quote_counter_scratch_data()
        + String::quote_counter_scratch_data()
        + Id::quote_counter_scratch_data() * 2
        + Vec::<Id>::quote_counter_scratch_data()
        + composition_counter_scratch_data()
        + size_of::<CloneFields>()
        + size_of::<Walk>()
        + size_of::<Result<Walk, ProviderError>>()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>() * 2
}

fn field_backing_counter<S, T: CloneBacking>(_: fn(&S) -> &T) -> usize {
    T::counter_scratch_data()
}

fn field_controls<S, T: CloneControls>(_: fn(&S) -> &T) -> Result<[usize; 2], ProviderError> {
    T::fresh_controls_data()
}

fn field_quote_counter<S, T: CloneControls>(_: fn(&S) -> &T) -> usize {
    size_of::<fn(&S) -> &T>() + T::quote_counter_scratch_data()
}

fn composition_counter_scratch_data() -> usize {
    size_of::<&[[usize; 2]]>()
        + size_of::<std::slice::Iter<'static, [usize; 2]>>()
        + size_of::<[usize; 2]>() * 3
        + size_of::<Result<[usize; 2], ProviderError>>()
        + size_of::<Option<usize>>() * 2
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 Hello result clone construction")
}
