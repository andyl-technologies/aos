//! Borrows initialized old-decoder summary scratch as explicit17 numeric DATA.
//!
//! This separate projection never changes the old11 accepted alias vocabulary.

use super::*;

impl HistoricalAliasSummary {
    /// Borrows all initialized summary fields without resetting decoder progress.
    pub(crate) fn current17_data(
        &self,
    ) -> (
        Option<u8>,
        usize,
        Option<[u8; 32]>,
        bool,
        Option<(u8, usize)>,
    ) {
        let Self {
            kind,
            layout,
            view_digest,
            in_progress,
            content_edge,
        } = self;
        let content = content_edge.map(|(kind, index)| {
            let tag = match kind {
                crate::client::compact_cursor::ContentGroupKind::Transfer => 0,
                crate::client::compact_cursor::ContentGroupKind::Object => 1,
            };
            (tag, index)
        });
        (
            kind.map(kind_tag),
            *layout,
            *view_digest,
            *in_progress,
            content,
        )
    }
}

fn kind_tag(kind: MetadataSharedKind) -> u8 {
    match kind {
        MetadataSharedKind::NativeRestoredPhysicalHold => 0,
        MetadataSharedKind::NativeRestoreCommitAttempt => 1,
        MetadataSharedKind::NativeRestoreInputCustody => 2,
        MetadataSharedKind::NativeRestorationObservationAttempt => 3,
        MetadataSharedKind::NativeRestoredSuffixObservationAttempt => 4,
        MetadataSharedKind::NativeRestoredProducerAttempt => 5,
        MetadataSharedKind::ProtocolOwner => 6,
        MetadataSharedKind::RegistrarEpoch => 7,
        MetadataSharedKind::RegistrarGate => 8,
        MetadataSharedKind::SelectedExtensions => 9,
        MetadataSharedKind::Codec => 10,
        MetadataSharedKind::NativePolicy => 11,
        MetadataSharedKind::HelloBank => 12,
        MetadataSharedKind::ContentBytes => 13,
        MetadataSharedKind::FrameBank => 14,
        MetadataSharedKind::NativeBoot => 15,
        MetadataSharedKind::PrivateBootstrapBank => 16,
        MetadataSharedKind::InstalledRegistry => 17,
        MetadataSharedKind::NativeSupervisor => 18,
        MetadataSharedKind::BlobLedger => 19,
        MetadataSharedKind::HostSupervisor => 20,
        MetadataSharedKind::OperationalDeadline => 21,
        MetadataSharedKind::ArchivedMapping => 22,
        MetadataSharedKind::NativeControlIdentity => 23,
        MetadataSharedKind::NativeFreshReportAttempt => 24,
        MetadataSharedKind::NativeRestorePrepareAttempt => 25,
        MetadataSharedKind::NativeRestorationActivationAttempt => 26,
        MetadataSharedKind::NativeRestorationUploadAttempt => 27,
        // Append explicit17 evidence tags without renumbering retained summaries.
        // Old11 admission remains governed by its separate closed row parser.
        MetadataSharedKind::HistoricalImportPolicy => 28,
        MetadataSharedKind::HistoricalImportBoot => 29,
        MetadataSharedKind::HistoricalImportFrames => 30,
        MetadataSharedKind::HistoricalImportBlobLedger => 31,
        MetadataSharedKind::HistoricalImportExtensions => 32,
        MetadataSharedKind::NativeRestoreResponse => 33,
        MetadataSharedKind::NativeRestoredSettledActionAttempt => 34,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialized_decoder_summary_keeps_failed_in_progress_without_reset() {
        let mut summaries = [HistoricalAliasSummary::default(); 1];
        {
            let mut aliases = ValidatedHistoricalAliases::validate(
                br#"[["native-policy",0]]"#,
                &mut summaries,
                1,
            )
            .unwrap();
            let mut views = aliases.views().unwrap();
            let group = views.begin(MetadataSharedKind::NativePolicy).unwrap();
            assert_eq!(group, 0);
        }
        let before = summaries[0].current17_data();
        assert_eq!(before.0, Some(11));
        assert!(before.3);
        assert!(before.2.is_none());
        assert_eq!(summaries[0].current17_data(), before);
    }

    #[test]
    fn explicit17_kinds_project_without_widening_old11_admission() {
        use crate::protocol_snapshot::restored_settled17::aliases::{
            RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
        };
        use MetadataSharedKind::*;

        let cases = [
            (HistoricalImportPolicy, "historical-import-policy", 28),
            (HistoricalImportBoot, "historical-import-boot", 29),
            (HistoricalImportFrames, "historical-import-frames", 30),
            (
                HistoricalImportBlobLedger,
                "historical-import-blob-ledger",
                31,
            ),
            (
                HistoricalImportExtensions,
                "historical-import-extensions",
                32,
            ),
            (NativeRestoreResponse, "native_restore_response", 33),
            (
                NativeRestoredSettledActionAttempt,
                "native-restored-settled-action-attempt",
                34,
            ),
        ];
        for (kind, name, tag) in cases {
            let summary = HistoricalAliasSummary {
                kind: Some(kind),
                layout: 24,
                view_digest: Some([7; 32]),
                in_progress: true,
                content_edge: None,
            };
            assert_eq!(
                summary.current17_data(),
                (Some(tag), 24, Some([7; 32]), true, None)
            );

            let input = format!("[[\"{name}\",0]]");
            let mut old_scratch = [HistoricalAliasSummary::default(); 1];
            assert!(
                ValidatedHistoricalAliases::validate(input.as_bytes(), &mut old_scratch, 1)
                    .is_err()
            );

            let mut current_scratch = [RestoredSettledNative17AliasSummary::default(); 1];
            let mut aliases = ValidatedRestoredSettledNative17Aliases::validate(
                input.as_bytes(),
                &mut current_scratch,
                1,
            )
            .unwrap();
            let mut views = aliases.views().unwrap();
            assert_eq!(
                views
                    .observe(kind, 24, b"actual-view", b"actual-rows")
                    .unwrap(),
                0
            );
            views.finish().unwrap();
        }
    }
}
