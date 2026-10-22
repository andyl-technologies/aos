//! Borrowed admission for the concrete Fid checkpoint wire.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;
use crate::snapshot_codec::seed::{BoundedVecSeed, TableAdmission, ValueSeed};

#[derive(Clone, Copy)]
pub(crate) struct FidSeed<'a, 'callback> {
    pub(crate) admission: &'a TableAdmission<'callback>,
}

impl<'de> DeserializeSeed<'de> for FidSeed<'_, '_> {
    type Value = FidEntryWire;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_struct("FidEntryWire", FIELDS, self)
    }
}

const FIELDS: &[&str] = &["path", "state"];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Path,
    State,
}

impl<'de> Visitor<'de> for FidSeed<'_, '_> {
    type Value = FidEntryWire;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the complete Fid checkpoint fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut path = None;
        let mut state = None;

        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Path => {
                    if path.is_some() {
                        return Err(serde::de::Error::duplicate_field("path"));
                    }
                    path = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_NINEP_PATH_COMPONENTS,
                    >::new(
                        ValueSeed::<String>::new(),
                        self.admission,
                    ))?);
                }
                Field::State => {
                    if state.is_some() {
                        return Err(serde::de::Error::duplicate_field("state"));
                    }
                    state = Some(map.next_value_seed(ValueSeed::<FidState>::new())?);
                }
            }
        }

        Ok(FidEntryWire {
            path: path.ok_or_else(|| serde::de::Error::missing_field("path"))?,
            state: state.ok_or_else(|| serde::de::Error::missing_field("state"))?,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let path = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_NINEP_PATH_COMPONENTS>::new(
                ValueSeed::<String>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let state = sequence
            .next_element_seed(ValueSeed::<FidState>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(FIELDS.len() + 1, &self));
        }

        Ok(FidEntryWire { path, state })
    }
}
