//! Owns precharged historical native Rc lookup entries and ordered alias claims.

use super::super::typed::{Ledger, invalid};
use super::{boot::HistoricalNativeBoot, policy::HistoricalNativePolicy};
use crate::{
    ProviderError,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
    transport::DecodedCompactOriginalFrames,
};
use std::rc::Rc;

/// Holds only reconstructed historical payload owners, never original authority.
#[derive(Default)]
pub(super) struct NativeSharedEntry {
    pub(super) policy: Option<Rc<HistoricalNativePolicy>>,
    pub(super) boot: Option<Rc<HistoricalNativeBoot>>,
    pub(super) frames: Option<Rc<DecodedCompactOriginalFrames>>,
    pub(super) blobs: Option<Rc<super::blob::HistoricalNativeBlobLedger>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NativeArchiveClass {
    Legacy11,
    Capture12,
    Startup13,
    StartupCapture14,
    InvocationCapture15,
}

impl NativeArchiveClass {
    pub(super) fn read(format: &str) -> Result<Self, ProviderError> {
        match format {
            "source-private.native-state/11" => Ok(Self::Legacy11),
            "source-private.native-state/12" => Ok(Self::Capture12),
            "source-private.native-state/13" => Ok(Self::Startup13),
            "source-private.native-state/14" => Ok(Self::StartupCapture14),
            "source-private.native-state/15" => Ok(Self::InvocationCapture15),
            _ => Err(invalid()),
        }
    }
    pub(super) fn startup(self) -> bool {
        matches!(
            self,
            Self::Startup13 | Self::StartupCapture14 | Self::InvocationCapture15
        )
    }
    pub(super) fn invocation(self) -> bool {
        self == Self::InvocationCapture15
    }

    pub(super) fn capture(self) -> bool {
        matches!(
            self,
            Self::Capture12 | Self::StartupCapture14 | Self::InvocationCapture15
        )
    }
}

pub(super) struct NativeLedger<'ledger, 'records, 'scratch, 'input, 'groups> {
    pub(super) class: Option<NativeArchiveClass>,
    pub(super) ledger: &'ledger mut Ledger<'records, 'scratch, 'input>,
    pub(super) groups: Option<&'groups mut [NativeSharedEntry]>,
    // Historical payload layouts can differ from original private live types.
    // Count them independently, conservatively per retained shared view.
    pub(super) historical_payload_layout_bytes: usize,
    pub(super) correlation_capacity_span: Option<(usize, usize)>,
}

impl NativeLedger<'_, '_, '_, '_, '_> {
    pub(super) fn select_class(&mut self, class: NativeArchiveClass) -> Result<(), ProviderError> {
        if self.class.is_some_and(|existing| existing != class) {
            return Err(invalid());
        }
        self.class = Some(class);
        Ok(())
    }

    pub(super) fn requires_startup_class(&self) -> Result<bool, ProviderError> {
        self.class
            .map(NativeArchiveClass::startup)
            .ok_or_else(invalid)
    }

    pub(super) fn requires_invocation_class(&self) -> Result<bool, ProviderError> {
        self.class
            .map(NativeArchiveClass::invocation)
            .ok_or_else(invalid)
    }

    fn payload<T>(&mut self) -> Result<(), ProviderError> {
        self.historical_payload_layout_bytes = self
            .historical_payload_layout_bytes
            .checked_add(std::mem::size_of::<T>())
            .ok_or_else(invalid)?;
        Ok(())
    }

    pub(super) fn begin(
        &mut self,
        kind: MetadataSharedKind,
        expected_layout: usize,
    ) -> Result<(usize, usize), ProviderError> {
        let start = self.ledger.rows.encoded_position();
        let layout = self.ledger.row(MetadataRecordKind::Shared, 1)?;
        if layout != expected_layout {
            return Err(invalid());
        }
        let group = self.ledger.shared_begin(kind)?;
        Ok((start, group))
    }

    pub(super) fn finish(
        &mut self,
        start: usize,
        group: usize,
        expected_layout: usize,
        view: &[u8],
    ) -> Result<(), ProviderError> {
        let rows = self.ledger.rows.encoded_between(start)?;
        self.ledger
            .shared_finish(group, expected_layout, view, rows)
    }

    pub(super) fn policy(
        &mut self,
        input: &[u8],
        build: bool,
    ) -> Result<Option<Rc<HistoricalNativePolicy>>, ProviderError> {
        // Refuse a new retained policy class before payload credit, alias rows
        // or any historical allocation is consumed. Inert policy18 fields do
        // not promote legacy native-state11/12 into startup-owning classes.
        if super::policy::requires_fresh_startup_class_data(input)?
            && !self.requires_startup_class()?
        {
            return Err(invalid());
        }
        self.payload::<HistoricalNativePolicy>()?;
        let layout = std::mem::size_of::<crate::reference_packet::Native5Policy>();
        let (start, group) = self.begin(MetadataSharedKind::NativePolicy, layout)?;
        let cached = self
            .groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(|entry| entry.policy.as_ref())
            .cloned();
        let policy = <HistoricalNativePolicy as super::super::typed::HistoricalType>::read(
            input,
            self.ledger,
            build && cached.is_none(),
        )?;
        self.finish(start, group, layout, input)?;
        if !build {
            return Ok(None);
        }
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }
        let policy = Rc::new(policy.ok_or_else(invalid)?);
        self.groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
            .ok_or_else(invalid)?
            .policy = Some(Rc::clone(&policy));
        Ok(Some(policy))
    }

    pub(super) fn boot(
        &mut self,
        input: &[u8],
        build: bool,
        layout: usize,
    ) -> Result<Option<Rc<HistoricalNativeBoot>>, ProviderError> {
        self.payload::<HistoricalNativeBoot>()?;
        let (start, group) = self.begin(MetadataSharedKind::NativeBoot, layout)?;
        let cached = self
            .groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(|entry| entry.boot.as_ref())
            .cloned();
        let boot = super::boot::read(input, self, build && cached.is_none())?;
        self.finish(start, group, layout, input)?;
        if !build {
            return Ok(None);
        }
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }
        let boot = Rc::new(boot.ok_or_else(invalid)?);
        self.groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
            .ok_or_else(invalid)?
            .boot = Some(Rc::clone(&boot));
        Ok(Some(boot))
    }

    pub(super) fn frames(
        &mut self,
        input: &[u8],
        build: bool,
        kind: MetadataSharedKind,
    ) -> Result<Option<Rc<DecodedCompactOriginalFrames>>, ProviderError> {
        self.payload::<DecodedCompactOriginalFrames>()?;
        let layout = crate::transport::original_frame_bank_layout();
        let (start, group) = self.begin(kind, layout)?;
        let plan = crate::transport::ValidatedCompactOriginalFrames::validate(
            input,
            self.ledger.limits.maximum_input_bytes,
            self.ledger.maximum_literal_bytes,
        )?;
        let mut fields = super::super::typed::Fields::array(input)?;
        for _ in 0..4 {
            super::super::state::next(&mut fields)?;
        }
        let bytes = usize::try_from(super::super::typed::unsigned(super::super::state::next(
            &mut fields,
        )?)?)
        .map_err(|_| invalid())?;
        let slots = usize::try_from(super::super::typed::unsigned(super::super::state::next(
            &mut fields,
        )?)?)
        .map_err(|_| invalid())?;
        if self.ledger.row(MetadataRecordKind::Vector, 1)? != bytes
            || self.ledger.row(
                MetadataRecordKind::Vector,
                crate::transport::original_frames::original_frame_slot_layout(),
            )? != slots
        {
            return Err(invalid());
        }
        self.ledger.literal_bytes = self
            .ledger
            .literal_bytes
            .checked_add(plan.allocated_bytes())
            .ok_or_else(invalid)?;
        if self.ledger.literal_bytes > self.ledger.maximum_literal_bytes {
            return Err(invalid());
        }
        let cached = self
            .groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(|entry| entry.frames.as_ref())
            .cloned();
        let frames = if build && cached.is_none() {
            Some(plan.reconstruct()?)
        } else {
            None
        };
        self.finish(start, group, layout, input)?;
        if !build {
            return Ok(None);
        }
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }
        let frames = Rc::new(frames.ok_or_else(invalid)?);
        self.groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
            .ok_or_else(invalid)?
            .frames = Some(Rc::clone(&frames));
        Ok(Some(frames))
    }
    pub(super) fn blobs(
        &mut self,
        input: &[u8],
        build: bool,
    ) -> Result<Option<Rc<super::blob::HistoricalNativeBlobLedger>>, ProviderError> {
        self.payload::<super::blob::HistoricalNativeBlobLedger>()?;
        let layout = crate::blob::original_blob_layouts().state;
        let (start, group) = self.begin(MetadataSharedKind::BlobLedger, layout)?;
        let cached = self
            .groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(|entry| entry.blobs.as_ref())
            .cloned();
        let state = super::blob::read_ledger(input, self, build && cached.is_none())?;
        self.finish(start, group, layout, input)?;
        if !build {
            return Ok(None);
        }
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }
        let state = Rc::new(state.ok_or_else(invalid)?);
        self.groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
            .ok_or_else(invalid)?
            .blobs = Some(Rc::clone(&state));
        Ok(Some(state))
    }
}

#[cfg(test)]
mod fresh_policy_class_tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::ValidatedMetadataRecords;

    #[test]
    fn fresh_policy_refuses_legacy_classes_before_payload_or_capacity_consumption()
    -> Result<(), ProviderError> {
        let rows = ValidatedMetadataRecords::validate(b"[]", 0, 0)?;
        for class in [NativeArchiveClass::Legacy11, NativeArchiveClass::Capture12] {
            let mut ledger = Ledger::new(
                rows.rows(),
                HistoricalJsonLimits {
                    maximum_input_bytes: 1024,
                    maximum_nodes: 16,
                    maximum_depth: 8,
                    maximum_owned_backing_bytes: 0,
                    maximum_tree_entries: 0,
                },
            );
            let mut native = NativeLedger {
                class: Some(class),
                ledger: &mut ledger,
                groups: None,
                historical_payload_layout_bytes: 0,
                correlation_capacity_span: None,
            };

            assert!(
                native
                    .policy(
                        br#"["source-private.native5-policy-owned-fresh-restore-allocation/18"]"#,
                        false,
                    )
                    .is_err()
            );
            assert_eq!(native.historical_payload_layout_bytes, 0);
            assert!(native.ledger.rows.next().is_none());
        }
        Ok(())
    }
}

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    header::<Rc<HistoricalNativePolicy>>()
        + header::<HistoricalNativePolicy>()
        + header::<Rc<HistoricalNativeBoot>>()
        + header::<HistoricalNativeBoot>()
        + header::<Rc<DecodedCompactOriginalFrames>>()
        + header::<DecodedCompactOriginalFrames>()
        + header::<Rc<super::blob::HistoricalNativeBlobLedger>>()
        + header::<super::blob::HistoricalNativeBlobLedger>()
        + size_of::<Option<NativeArchiveClass>>()
        + size_of::<Option<&'static NativeSharedEntry>>()
        + size_of::<Option<&'static Rc<HistoricalNativePolicy>>>()
        + size_of::<Option<&'static Rc<HistoricalNativeBoot>>>()
        + size_of::<Option<&'static Rc<DecodedCompactOriginalFrames>>>()
        + size_of::<Option<&'static Rc<super::blob::HistoricalNativeBlobLedger>>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
}
