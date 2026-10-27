//! Borrowed admission for the concrete Server checkpoint wire.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;
use crate::snapshot_codec::seed::{BoundedVecSeed, PairSeed, TableAdmission, ValueSeed};

#[derive(Clone, Copy)]
pub(crate) struct ServerSeed<'a, 'callback> {
    pub(crate) admission: &'a TableAdmission<'callback>,
}

impl<'de> DeserializeSeed<'de> for ServerSeed<'_, '_> {
    type Value = NinepServerWire;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_struct("NinepServerWire", FIELDS, self)
    }
}

const FIELDS: &[&str] = &["msize", "negotiated", "fids"];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Msize,
    Negotiated,
    Fids,
}

impl<'de> Visitor<'de> for ServerSeed<'_, '_> {
    type Value = NinepServerWire;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the complete Server checkpoint fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut msize = None;
        let mut negotiated = None;
        let mut fids = None;

        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Msize => {
                    if msize.is_some() {
                        return Err(serde::de::Error::duplicate_field("msize"));
                    }
                    msize = Some(map.next_value_seed(ValueSeed::<u32>::new())?);
                }
                Field::Negotiated => {
                    if negotiated.is_some() {
                        return Err(serde::de::Error::duplicate_field("negotiated"));
                    }
                    negotiated = Some(map.next_value_seed(ValueSeed::<bool>::new())?);
                }
                Field::Fids => {
                    if fids.is_some() {
                        return Err(serde::de::Error::duplicate_field("fids"));
                    }
                    fids = Some(
                        map.next_value_seed(BoundedVecSeed::<_, MAX_NINEP_FIDS>::new(
                            PairSeed(
                                ValueSeed::<u32>::new(),
                                super::fid_seed::FidSeed {
                                    admission: self.admission,
                                },
                            ),
                            self.admission,
                        ))?,
                    );
                }
            }
        }

        Ok(NinepServerWire {
            msize: msize.ok_or_else(|| serde::de::Error::missing_field("msize"))?,
            negotiated: negotiated.ok_or_else(|| serde::de::Error::missing_field("negotiated"))?,
            fids: fids.ok_or_else(|| serde::de::Error::missing_field("fids"))?,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let msize = sequence
            .next_element_seed(ValueSeed::<u32>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let negotiated = sequence
            .next_element_seed(ValueSeed::<bool>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        let fids = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_NINEP_FIDS>::new(
                PairSeed(
                    ValueSeed::<u32>::new(),
                    super::fid_seed::FidSeed {
                        admission: self.admission,
                    },
                ),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(FIELDS.len() + 1, &self));
        }

        Ok(NinepServerWire {
            msize,
            negotiated,
            fids,
        })
    }
}
