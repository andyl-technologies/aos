//! Shares compiled schema field rosters between encoding and preallocation count.
//!
//! The borrowed variants have no owned backing or custom byte formatters. Their
//! same Serialize implementation drives the existing JSON schema constructor
//! and the fixed no-output requested-storage visitor before that constructor.

use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};

pub(crate) enum ContractValue<'a> {
    Text(&'a str),
    Number(u64),
    Array(&'a [Self]),
    Object(&'a [(&'a str, Self)]),
}

impl Serialize for ContractValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Number(value) => serializer.serialize_u64(*value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in *values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in *values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}
