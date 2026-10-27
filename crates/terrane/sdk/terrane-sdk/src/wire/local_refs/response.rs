//! Encodes complete canonical ref responses and accounts represented data bytes.
//!
//! Counts describe response fields, not peak backend materialization memory or
//! transport framing. Storage policy and transport bounds remain independent.

use connectrpc::ConnectError;
use terrane_format::refs::RefRecord;

use super::{LocalRefLimits, read::protocol};
use crate::wire::{refs::RefCodec, status::Outcome, v1};

pub(super) fn state(
    codec: RefCodec,
    profile: &str,
    name: String,
    record: &RefRecord,
    trace: &str,
) -> Result<v1::RefState, ConnectError> {
    let value = codec
        .encode_value(record, profile)
        .map_err(|_| protocol(Outcome::Internal, trace))?;
    Ok(v1::RefState {
        name,
        value: value.into(),
        home: v1::Locality {
            region: record.home.region.clone().unwrap_or_default(),
            zone: record.home.zone.clone().unwrap_or_default(),
            host: record.home.host.clone().unwrap_or_default(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })
}

pub(super) struct ResponseBudget {
    limits: LocalRefLimits,
    entries: usize,
    bytes: usize,
}

impl ResponseBudget {
    pub(super) fn new(limits: LocalRefLimits) -> Self {
        Self {
            limits,
            entries: 0,
            bytes: 0,
        }
    }

    pub(super) fn state(&mut self, state: &v1::RefState, trace: &str) -> Result<(), ConnectError> {
        self.entry(trace)?;
        let value = state.value.as_option();
        let home = state.home.as_option();
        self.add(
            [
                state.name.len(),
                value.map_or(0, |value| value.canonical_ref_record.len()),
                value.map_or(0, |value| value.profile.len()),
                value
                    .and_then(|value| value.commit.as_option())
                    .map_or(0, |hash| hash.value.len()),
                home.map_or(0, |home| home.region.len()),
                home.map_or(0, |home| home.zone.len()),
                home.map_or(0, |home| home.host.len()),
            ],
            trace,
        )
    }

    pub(super) fn log(&mut self, entry: &v1::RefLogEntry, trace: &str) -> Result<(), ConnectError> {
        self.entry(trace)?;
        let value = entry.value.as_option();
        self.add(
            [
                entry.canonical_ref_log_record.len(),
                entry.principal.len(),
                entry.message.len(),
                value.map_or(0, |value| value.canonical_ref_record.len()),
                value.map_or(0, |value| value.profile.len()),
                value
                    .and_then(|value| value.commit.as_option())
                    .map_or(0, |hash| hash.value.len()),
            ],
            trace,
        )
    }

    fn entry(&mut self, trace: &str) -> Result<(), ConnectError> {
        // Check before incrementing, including the representable maximum.
        if self.entries >= self.limits.max_entries.get() {
            return Err(limit(
                "ref-response-entries",
                self.limits.max_entries.get(),
                self.entries.saturating_add(1),
                trace,
            ));
        }
        self.entries += 1;
        Ok(())
    }

    fn add<const N: usize>(
        &mut self,
        lengths: [usize; N],
        trace: &str,
    ) -> Result<(), ConnectError> {
        for length in lengths {
            self.bytes = self
                .bytes
                .checked_add(length)
                .ok_or_else(|| protocol(Outcome::Internal, trace))?;
        }
        if self.bytes > self.limits.max_content_bytes.get() {
            return Err(limit(
                "ref-response-bytes",
                self.limits.max_content_bytes.get(),
                self.bytes,
                trace,
            ));
        }
        Ok(())
    }
}

pub(super) fn limit(name: &str, limit: usize, requested: usize, trace: &str) -> ConnectError {
    protocol(
        Outcome::Malformed(v1::Limit {
            name: name.into(),
            limit: limit as u64,
            requested: requested as u64,
            ..Default::default()
        }),
        trace,
    )
}
