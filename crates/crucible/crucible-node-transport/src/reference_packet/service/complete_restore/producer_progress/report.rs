//! Serializes the closed borrowed prepublication Producer report.

use super::*;
use crate::envelope::Envelope;
use serde::ser::SerializeStruct;

/// Borrows actual complete evidence without constructing publication authority.
///
/// The Source first validates the completed pair and same-operation common
/// outcome under its real currentness fence, then retains the actual Value and
/// canonical bytes before lending those bytes to durable publication. This
/// object deliberately has no deserializer or authority-bearing constructor.
pub struct PacketRestoredProducerOperationReportData<'a> {
    /// Names the genuine pending operation independently of copied wire fields.
    pub operation: &'a Id,
    /// Borrows the complete actual assigned Begin envelope.
    pub begin_original: &'a Envelope,
    /// Borrows its complete actual completed terminal envelope.
    pub begin_terminal: &'a Envelope,
    /// Borrows the complete later assigned Poll envelope.
    pub poll_original: &'a Envelope,
    /// Borrows its complete terminal retaining the original Begin outcome.
    pub poll_terminal: &'a Envelope,
    /// Names the actual complete restored12 canonical body.
    pub measurement: &'a ContentRef,
    /// Borrows the complete restored12 body, including immutable Commit ancestry.
    pub restored: &'a PacketNativeRestoredRecord,
    /// Borrows the full Producer2 model, grant and payload references.
    pub producer: &'a PacketNativeRecord,
    /// Names the actual uploaded common execution authorization.
    pub input_authorization: &'a ContentRef,
}

pub(super) const REPORT_FIELDS: [&str; 10] = [
    "schema",
    "operation",
    "begin_original",
    "begin_terminal",
    "poll_original",
    "poll_terminal",
    "measurement",
    "restored",
    "producer",
    "input_authorization",
];
pub(super) const REPORT_SCHEMA: &str = "crucible/restored-producer-operation-report/1";

impl serde::Serialize for PacketRestoredProducerOperationReportData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut report = serializer.serialize_struct("RestoredProducerOperationReport", 10)?;
        report.serialize_field(REPORT_FIELDS[0], REPORT_SCHEMA)?;
        report.serialize_field(REPORT_FIELDS[1], self.operation)?;
        report.serialize_field(REPORT_FIELDS[2], self.begin_original)?;
        report.serialize_field(REPORT_FIELDS[3], self.begin_terminal)?;
        report.serialize_field(REPORT_FIELDS[4], self.poll_original)?;
        report.serialize_field(REPORT_FIELDS[5], self.poll_terminal)?;
        report.serialize_field(REPORT_FIELDS[6], self.measurement)?;
        report.serialize_field(REPORT_FIELDS[7], self.restored)?;
        report.serialize_field(REPORT_FIELDS[8], self.producer)?;
        report.serialize_field(REPORT_FIELDS[9], self.input_authorization)?;
        report.end()
    }
}
