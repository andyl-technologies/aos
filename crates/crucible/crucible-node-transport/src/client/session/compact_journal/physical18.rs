//! Pairs the complete compact SDK custody owner with an inert historical reader.
//!
//! ```text
//! ["source-private.compact-custody/18", capacity_format,
//!  [maximum_requests,maximum_bytes,retained_bytes,maximum_bank_bytes,
//!   controller_originals,provider_originals,content8,pending,unexpected], rows]
//! original = [request_bank18,identity,response_bank18_or_null]
//! pending = null | [origin,envelope]
//! unexpected = null | [envelope,["notification",body]]
//!            | [envelope,["bootstrap-request",request]]
//!            | [envelope,["bootstrap-response",shape,typed_result_or_null]]
//! ```
//!
//! Capacity rows come from the defining custody census, including independently
//! owned typed failure bodies. Content8 preserves its complete local Rc graph;
//! no other custody field shares those allocations. Imported history has no
//! extractor into live custody and creates no Source, receipt or native rights.

use super::{CompactClientCustody, CompactClientOriginal, PendingEnvelope};
use crate::ProviderError;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::retained_metadata::{MetadataObserver, records::*};
use serde::{Serialize, Serializer, ser::SerializeMap};

mod read;
mod typed;

const TAG: &str = "source-private.compact-custody/18";

/// Restricts complete historical DATA construction without granting allocation.
///
/// The caller independently admits encoded input, all retained and failed-prefix
/// owners, tree nodes, Box/control-block geometry, codec controls and machine
/// stack before decoding. Validation temporarily constructs at most one bank at
/// a time; its full ceiling and content reconstruction's group-index vectors
/// must be funded in addition to the eventual history.
#[derive(Clone, Copy, Debug)]
pub struct CompactCustody18Limits {
    /// Bounds the entire encoded history, including its capacity records.
    pub maximum_input_bytes: usize,
    /// Bounds the complete fixed-layout capacity-record population.
    pub maximum_capacity_rows: usize,
    /// Bounds summed String/Vec capacities, conservatively counting Rc views.
    pub maximum_backing_capacity_bytes: usize,
    /// Bounds each exact compact bank, including preflight's temporary bank.
    pub maximum_envelope_bank_bytes: usize,
    /// Bounds ordinary historical JSON fields and their requested backing.
    pub json: crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits,
    /// Bounds the complete content8 byte, alias and metadata populations.
    pub content: crate::client::compact_metadata8::CompactMetadata8Limits,
}

impl CompactClientCustody {
    /// Records actual capacities and borrows the complete physical18 history.
    ///
    /// The caller preowns and funds `records`, including partial capture on
    /// refusal. Walking never grows it. Holding the returned view prevents
    /// mutation of either the original custody or its captured capacity rows.
    /// Serialization output, controls and transient work need separate funding.
    ///
    /// # Errors
    /// Refuses unsupported compact banks, retained frame variants, census
    /// overflow or an exhausted/unreserved record bank.
    pub fn physical_custody18_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        for original in self.controller.values().chain(self.provider.values()) {
            original.request.physical18_data()?;
            if let Some(response) = &original.response {
                response.physical18_data()?;
            }
        }

        let mut observer = MetadataObserver::recording(records);
        self.observe_owned_metadata(&mut observer)?;
        Ok(CustodyView {
            custody: self,
            records,
        })
    }
}

struct CustodyView<'a> {
    custody: &'a CompactClientCustody,
    records: &'a MetadataRecordBank,
}

impl Serialize for CustodyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            TAG,
            METADATA_CAPACITY_RECORD_FORMAT,
            CustodyFields(self.custody),
            self.records.rows(),
        )
            .serialize(serializer)
    }
}

struct CustodyFields<'a>(&'a CompactClientCustody);

impl Serialize for CustodyFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CompactClientCustody {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            maximum_envelope_bank_bytes,
            controller,
            provider,
            content,
            pending,
            unexpected,
        } = self.0;
        (
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            maximum_envelope_bank_bytes,
            Originals(controller),
            Originals(provider),
            content.original_compact_metadata8_view(),
            pending
                .as_ref()
                .map(|PendingEnvelope { origin, envelope }| (origin, envelope)),
            unexpected.as_ref().map(FrameView),
        )
            .serialize(serializer)
    }
}

struct Originals<'a>(
    &'a std::collections::BTreeMap<crucible_node_format::Id, CompactClientOriginal>,
);

impl Serialize for Originals<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (id, original) in self.0 {
            let CompactClientOriginal {
                request,
                identity,
                response,
            } = original;
            let request = request
                .physical18_data()
                .map_err(serde::ser::Error::custom)?;
            let response = response
                .as_ref()
                .map(crate::client::compact_json::CompactJson::physical18_data)
                .transpose()
                .map_err(serde::ser::Error::custom)?;
            map.serialize_entry(id, &(request, identity, response))?;
        }
        map.end()
    }
}

struct FrameView<'a>(&'a ReceivedFrame);

impl Serialize for FrameView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        struct Body<'a>(&'a ReceivedBody);
        impl Serialize for Body<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use typed::BootstrapBody;
                match self.0 {
                    ReceivedBody::Notification(body) => {
                        ("notification", body).serialize(serializer)
                    }
                    ReceivedBody::NativeImport18Bootstrap(body) => match body.as_ref() {
                        BootstrapBody::Request(request) => {
                            ("bootstrap-request", request).serialize(serializer)
                        }
                        BootstrapBody::Response(response) => {
                            ("bootstrap-response", &response.shape, &response.result)
                                .serialize(serializer)
                        }
                    },
                    ReceivedBody::Request(_) | ReceivedBody::Response(_) => Err(
                        serde::ser::Error::custom("unsupported compact custody18 retained frame"),
                    ),
                }
            }
        }

        let ReceivedFrame { envelope, body } = self.0;
        let mut fields = serializer.serialize_tuple(2)?;
        fields.serialize_element(envelope)?;
        fields.serialize_element(&Body(body))?;
        fields.end()
    }
}

/// Owns the entire historical custody without an operation or installation API.
///
/// Both journals, lifetime credit, content aliases, pending original and typed
/// quarantine survive reconstruction. Even invalid typed failure prefixes remain
/// DATA: decoding does not authenticate their schemas, identities or receipts.
pub struct HistoricalCompactCustody18 {
    custody: CompactClientCustody,
}

impl HistoricalCompactCustody18 {
    /// Reconstructs complete historical DATA after checking the entire roster.
    ///
    /// Preflight borrows ordinary JSON and content8 without constructing their
    /// owners, and decodes/drops one bank at a time. A second pass constructs
    /// final owners directly. Encoded input remains independently retained.
    /// There is no conversion to live SDK, Source, Birth or native authority.
    ///
    /// # Errors
    /// Refuses unknown editions, incomplete/extra fields, invalid or mismatched
    /// capacity rows, limits, bank geometry, aliases or failed exact allocations.
    pub fn decode(input: &[u8], limits: CompactCustody18Limits) -> Result<Self, ProviderError> {
        read::decode(input, limits).map(|custody| Self { custody })
    }

    /// Reports unchanged lifetime ceilings and consumed canonical-byte credit.
    pub fn journal_limits_data(&self) -> [usize; 4] {
        [
            self.custody.maximum_requests,
            self.custody.maximum_bytes,
            self.custody.retained_bytes,
            self.custody.maximum_envelope_bank_bytes,
        ]
    }

    /// Borrows one complete original as DATA in its original request namespace.
    pub fn original_data(
        &self,
        origin: crate::envelope::RequestOrigin,
        id: &crucible_node_format::Id,
    ) -> Option<&CompactClientOriginal> {
        self.custody.original(origin, id)
    }

    /// Borrows all complete content8 history without a mutable live-store handle.
    pub fn content_data(&self) -> &crate::client::ClientContent {
        &self.custody.content
    }

    /// Borrows the independently owned received original and its namespace.
    pub fn pending_envelope_data(
        &self,
    ) -> Option<(crate::envelope::RequestOrigin, &crate::envelope::Envelope)> {
        self.custody.pending_envelope()
    }

    /// Borrows both the raw envelope and its independent typed failure body.
    pub fn unexpected_frame_data(&self) -> Option<&ReceivedFrame> {
        self.custody.unexpected_frame()
    }

    /// Records and borrows the same complete physical18 history.
    ///
    /// # Errors
    /// Refuses an insufficient record bank or a changed defining census.
    pub fn physical_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.custody.physical_custody18_data(records)
    }

    /// Counts independently retained fields using the original defining census.
    ///
    /// # Errors
    /// Refuses checked overflow or unsupported retained metadata.
    pub fn retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.custody.retained_metadata_facts()
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("compact custody18 historical DATA grammar")
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact custody18 historical DATA limits")
}

#[cfg(test)]
pub(super) mod tests;
