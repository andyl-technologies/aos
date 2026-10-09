//! Borrowed admission for the concrete NinepWire checkpoint wire.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;
use crate::snapshot_codec::seed::{BoundedVecSeed, TableAdmission, ValueSeed};

#[derive(Clone, Copy)]
pub(crate) struct NinepWireSeed<'a, 'callback> {
    pub(crate) admission: &'a TableAdmission<'callback>,
}

impl<'de> DeserializeSeed<'de> for NinepWireSeed<'_, '_> {
    type Value = NinepSnapshotWire;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_struct("NinepSnapshotWire", FIELDS, self)
    }
}

const FIELDS: &[&str] = &[
    "core",
    "server",
    "latency",
    "require_fault_directives",
    "directives",
    "visibility",
    "virtual_fids",
    "session_epoch",
];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Core,
    Server,
    Latency,
    RequireFaultDirectives,
    Directives,
    Visibility,
    VirtualFids,
    SessionEpoch,
}

impl<'de> Visitor<'de> for NinepWireSeed<'_, '_> {
    type Value = NinepSnapshotWire;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the complete NinepWire checkpoint fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut core = None;
        let mut server = None;
        let mut latency = None;
        let mut require_fault_directives = None;
        let mut directives = None;
        let mut visibility = None;
        let mut virtual_fids = None;
        let mut session_epoch = None;

        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Core => {
                    if core.is_some() {
                        return Err(serde::de::Error::duplicate_field("core"));
                    }
                    core = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_NINEP_SNAPSHOT_BYTES,
                    >::new(
                        ValueSeed::<u8>::new(), self.admission
                    ))?);
                }
                Field::Server => {
                    if server.is_some() {
                        return Err(serde::de::Error::duplicate_field("server"));
                    }
                    server = Some(map.next_value_seed(super::server_seed::ServerSeed {
                        admission: self.admission,
                    })?);
                }
                Field::Latency => {
                    if latency.is_some() {
                        return Err(serde::de::Error::duplicate_field("latency"));
                    }
                    latency = Some(map.next_value_seed(ValueSeed::<[u64; 3]>::new())?);
                }
                Field::RequireFaultDirectives => {
                    if require_fault_directives.is_some() {
                        return Err(serde::de::Error::duplicate_field(
                            "require_fault_directives",
                        ));
                    }
                    require_fault_directives = Some(map.next_value_seed(ValueSeed::<bool>::new())?);
                }
                Field::Directives => {
                    if directives.is_some() {
                        return Err(serde::de::Error::duplicate_field("directives"));
                    }
                    directives = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_NINEP_DIRECTIVES,
                    >::new(
                        ValueSeed::<(NinepRequestIdentity, ResolvedNinepRequestDirective)>::new(),
                        self.admission,
                    ))?);
                }
                Field::Visibility => {
                    if visibility.is_some() {
                        return Err(serde::de::Error::duplicate_field("visibility"));
                    }
                    visibility =
                        Some(map.next_value_seed(ValueSeed::<NinepVisibilityState>::new())?);
                }
                Field::VirtualFids => {
                    if virtual_fids.is_some() {
                        return Err(serde::de::Error::duplicate_field("virtual_fids"));
                    }
                    virtual_fids = Some(map.next_value_seed(
                        BoundedVecSeed::<_, MAX_NINEP_FIDS>::new(
                            ValueSeed::<(u32, NinepVirtualFid)>::new(),
                            self.admission,
                        ),
                    )?);
                }
                Field::SessionEpoch => {
                    if session_epoch.is_some() {
                        return Err(serde::de::Error::duplicate_field("session_epoch"));
                    }
                    session_epoch = Some(map.next_value_seed(ValueSeed::<u64>::new())?);
                }
            }
        }

        Ok(NinepSnapshotWire {
            core: core.ok_or_else(|| serde::de::Error::missing_field("core"))?,
            server: server.ok_or_else(|| serde::de::Error::missing_field("server"))?,
            latency: latency.ok_or_else(|| serde::de::Error::missing_field("latency"))?,
            require_fault_directives: require_fault_directives
                .ok_or_else(|| serde::de::Error::missing_field("require_fault_directives"))?,
            directives: directives.ok_or_else(|| serde::de::Error::missing_field("directives"))?,
            visibility: visibility.ok_or_else(|| serde::de::Error::missing_field("visibility"))?,
            virtual_fids: virtual_fids
                .ok_or_else(|| serde::de::Error::missing_field("virtual_fids"))?,
            session_epoch: session_epoch
                .ok_or_else(|| serde::de::Error::missing_field("session_epoch"))?,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let core = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_NINEP_SNAPSHOT_BYTES>::new(
                ValueSeed::<u8>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let server = sequence
            .next_element_seed(super::server_seed::ServerSeed {
                admission: self.admission,
            })?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        let latency = sequence
            .next_element_seed(ValueSeed::<[u64; 3]>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        let require_fault_directives = sequence
            .next_element_seed(ValueSeed::<bool>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
        let directives = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_NINEP_DIRECTIVES>::new(
                ValueSeed::<(NinepRequestIdentity, ResolvedNinepRequestDirective)>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
        let visibility = sequence
            .next_element_seed(ValueSeed::<NinepVisibilityState>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
        let virtual_fids = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_NINEP_FIDS>::new(
                ValueSeed::<(u32, NinepVirtualFid)>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
        let session_epoch = sequence
            .next_element_seed(ValueSeed::<u64>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(7, &self))?;
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(FIELDS.len() + 1, &self));
        }

        Ok(NinepSnapshotWire {
            core,
            server,
            latency,
            require_fault_directives,
            directives,
            visibility,
            virtual_fids,
            session_epoch,
        })
    }
}

#[cfg(test)]
#[path = "wire_seed/tests.rs"]
mod tests;
