//! Composes actual field cloning and fresh configuration initializer headers.
//!
//! Actual tree populations supply their recursive node windows separately. The
//! 64-container JSON profile admits one additional terminal scalar window.
//! Summed sequential field windows are conservative requested control data,
//! excluding allocator residency and compiler frames.

use super::{ProviderError, string_data, total, vector_data};
use crate::handshake::{Limits, NegotiationPolicy, TrustedInstallation};
use crucible_node_format::{
    ArtifactIdentity, ContentRef, HashRef, Id, ImplementationIdentity, SchemaRef, U64,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::mem::size_of;

type JsonTransientFields = [usize; 5];
type JsonScratchFields = [usize; 6];

/// Names the actual concrete field clone control suppliers below.
pub(in super::super) trait CloneControls {
    /// Returns fresh-clone transient and scratch controls, excluding backing.
    ///
    /// # Errors
    /// Refuses unsupported pinned source layouts or checked arithmetic overflow.
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError>;

    /// Names this concrete typed composition's actual quote arrays and results.
    fn quote_counter_scratch_data() -> usize;
}

impl CloneControls for String {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        string_data()
    }

    fn quote_counter_scratch_data() -> usize {
        super::quote_counter_scratch_data()
    }
}

impl CloneControls for Id {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        combine(&[
            [size_of::<Self>(), size_of::<&Self>()], // derived Clone result/receiver
            String::fresh_controls_data()?,
        ])
    }

    fn quote_counter_scratch_data() -> usize {
        size_of::<[[usize; 2]; 2]>()
            + composition_counter_scratch_data()
            + String::quote_counter_scratch_data()
    }
}

macro_rules! copied {
    ($($type:ty),+ $(,)?) => { $(
        impl CloneControls for $type {
            fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
                Ok([size_of::<Self>(), size_of::<&Self>()])
            }

            fn quote_counter_scratch_data() -> usize {
                size_of::<[usize; 2]>() + size_of::<Result<[usize; 2], ProviderError>>()
            }
        }
    )+ };
}

copied!(U64, u16, [u8; 32]);

impl<T: CloneControls + 'static> CloneControls for Vec<T> {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        combine(&[vector_data::<T>()?, T::fresh_controls_data()?])
    }

    fn quote_counter_scratch_data() -> usize {
        size_of::<[[usize; 2]; 2]>()
            + composition_counter_scratch_data()
            + super::quote_counter_scratch_data()
            + T::quote_counter_scratch_data()
    }
}

impl<T: CloneControls> CloneControls for BTreeMap<String, T> {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        // The population walk adds actual map/node windows. Only the actual
        // key and value clone DAGs join this typed field composition here.
        combine(&[String::fresh_controls_data()?, T::fresh_controls_data()?])
    }

    fn quote_counter_scratch_data() -> usize {
        size_of::<[[usize; 2]; 2]>()
            + composition_counter_scratch_data()
            + String::quote_counter_scratch_data()
            + T::quote_counter_scratch_data()
    }
}

impl CloneControls for Value {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        let vector = vector_data::<Value>()?;
        let transient: JsonTransientFields = [
            size_of::<Value>(),              // cloned child return
            size_of::<Value>(),              // actual variant initializer
            size_of::<Value>(),              // Value::clone return
            size_of::<Map<String, Value>>(), // object backend Clone return
            vector[0],
        ];
        let scratch: JsonScratchFields = [
            size_of::<&Value>(),
            size_of::<&Map<String, Value>>(),
            size_of::<&Vec<Value>>(),
            size_of::<&String>(),
            size_of::<&serde_json::Number>(),
            vector[1],
        ];
        let json = [total(&transient)?, total(&scratch)?];
        let windows = 64usize.checked_add(1).ok_or_else(super::refused)?;
        combine(&[
            [
                json[0].checked_mul(windows).ok_or_else(super::refused)?,
                json[1].checked_mul(windows).ok_or_else(super::refused)?,
            ],
            String::fresh_controls_data()?,
        ])
    }

    fn quote_counter_scratch_data() -> usize {
        // This quote multiplies a fixed JSON window; it does not recursively
        // invoke its own typed supplier or construct a Value.
        size_of::<JsonTransientFields>()
            + size_of::<JsonScratchFields>()
            + size_of::<[[usize; 2]; 2]>()
            + size_of::<[usize; 2]>() * 2
            + size_of::<usize>()
            + composition_counter_scratch_data()
            + super::quote_counter_scratch_data()
            + String::quote_counter_scratch_data()
    }
}

macro_rules! fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl CloneControls for $type {
            fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
                const ROWS: usize = 1 $(+ { let _ = stringify!($field); 1 })+;
                let rows: [[usize; 2]; ROWS] = [
                    [size_of::<Self>(), size_of::<&Self>()],
                    $(field_controls(|value: &Self| &value.$field)?,)+
                ];
                combine(&rows)
            }

            fn quote_counter_scratch_data() -> usize {
                const ROWS: usize = 1 $(+ { let _ = stringify!($field); 1 })+;
                size_of::<[[usize; 2]; ROWS]>() + composition_counter_scratch_data()
                    $(+ field_quote_counter(|value: &Self| &value.$field))+
            }
        }

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
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
impl CloneControls for NegotiationPolicy {
    fn fresh_controls_data() -> Result<[usize; 2], ProviderError> {
        // The native initializer uses Vec::new for required_schemas. It never
        // clones a required SchemaRef or reuses a general policy Clone quote.
        let rows: [[usize; 2]; 7] = [
            [size_of::<Self>(), size_of::<&Self>()],
            Vec::<Id>::fresh_controls_data()?,
            Vec::<Id>::fresh_controls_data()?,
            Limits::fresh_controls_data()?,
            [size_of::<Vec<SchemaRef>>(), 0],
            ContentRef::fresh_controls_data()?,
            BTreeMap::<String, Id>::fresh_controls_data()?,
        ];
        combine(&rows)
    }

    fn quote_counter_scratch_data() -> usize {
        size_of::<[[usize; 2]; 7]>()
            + composition_counter_scratch_data()
            + Vec::<Id>::quote_counter_scratch_data() * 2
            + Limits::quote_counter_scratch_data()
            + ContentRef::quote_counter_scratch_data()
            + BTreeMap::<String, Id>::quote_counter_scratch_data()
    }
}

const _: fn(&NegotiationPolicy) = |value| {
    let NegotiationPolicy {
        supported_features: _,
        required_features: _,
        provider_limits: _,
        required_schemas: _,
        required_guarantees: _,
        envelope_extension_features: _,
    } = value;
};

pub(in super::super) fn combine(rows: &[[usize; 2]]) -> Result<[usize; 2], ProviderError> {
    rows.iter().try_fold([0usize; 2], |sum, row| {
        Ok([
            sum[0].checked_add(row[0]).ok_or_else(super::refused)?,
            sum[1].checked_add(row[1]).ok_or_else(super::refused)?,
        ])
    })
}
