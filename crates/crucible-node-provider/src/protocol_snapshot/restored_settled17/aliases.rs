//! Checks complete native17 shared groups without widening old11 vocabulary.
//!
//! Group indices describe aliases inside one archive. They cannot identify an
//! original actor or enroll a live registrar, policy or connection. A caller
//! precharges the summary slice before invoking the complete grammar pass.
//!
//! ```json
//! [["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0]]
//! ```

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid, plain_string};
use crate::retained_metadata::aliases::MetadataSharedKind;

/// Stores one admitted first-group summary without retaining process addresses.
#[derive(Clone, Copy, Default)]
pub struct RestoredSettledNative17AliasSummary {
    kind: Option<MetadataSharedKind>,
    layout: usize,
    view_digest: Option<[u8; 32]>,
    in_progress: bool,
    definition_pass: usize,
    content_edge: Option<(crate::client::compact_cursor::ContentGroupKind, usize)>,
}

/// Borrows a completely validated local alias roster and precharged summaries.
pub struct ValidatedRestoredSettledNative17Aliases<'input, 'scratch> {
    input: &'input [u8],
    summaries: &'scratch mut [RestoredSettledNative17AliasSummary],
    rows: usize,
    groups: usize,
    pass_in_progress: bool,
    pass_number: usize,
}

impl<'input, 'scratch> ValidatedRestoredSettledNative17Aliases<'input, 'scratch> {
    /// Checks every row and first-group relation without allocating storage.
    ///
    /// The supplied slice is private planning storage. Its physical allocation,
    /// compiler stack and any eventual Rc control blocks need separate admission.
    ///
    /// # Errors
    /// Refuses malformed framing, unknown kinds, forward groups, inconsistent
    /// repeated kinds, excess rows or insufficient precharged summary storage.
    pub fn validate(
        input: &'input [u8],
        summaries: &'scratch mut [RestoredSettledNative17AliasSummary],
        maximum_rows: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_rows == 0 || maximum_rows > 131072 || summaries.len() > 131072 {
            return Err(invalid());
        }
        if summaries.iter().any(|summary| {
            summary.kind.is_some()
                || summary.layout != 0
                || summary.view_digest.is_some()
                || summary.in_progress
                || summary.definition_pass != 0
                || summary.content_edge.is_some()
        }) {
            return Err(invalid());
        }
        let mut fields = Fields::array(input)?;
        let mut rows = 0usize;
        let mut groups = 0usize;
        while let Some(field) = fields.next()? {
            let (kind, group) = row(field)?;
            rows = rows.checked_add(1).ok_or_else(invalid)?;
            if rows > maximum_rows || group > groups {
                return Err(invalid());
            }
            if group == groups {
                let summary = summaries.get_mut(groups).ok_or_else(invalid)?;
                summary.kind = Some(kind);
                groups += 1;
            } else if summaries.get(group).and_then(|summary| summary.kind) != Some(kind) {
                return Err(invalid());
            }
        }
        Ok(Self {
            input,
            summaries,
            rows,
            groups,
            pass_in_progress: false,
            pass_number: 0,
        })
    }

    /// Reports checked shared-view rows, including repeated aliases.
    pub const fn row_count(&self) -> usize {
        self.rows
    }

    /// Reports checked independent first groups, including equal distinct owners.
    pub const fn group_count(&self) -> usize {
        self.groups
    }

    /// Starts or replays a source-order pass after the previous pass finished.
    ///
    /// Successful replay compares against the retained first-view summaries.
    /// A dropped, failed or unfinished pass cannot reset its partial state.
    ///
    /// # Errors
    /// Refuses a prior pass that did not finish successfully or malformed framing.
    pub fn views(
        &mut self,
    ) -> Result<RestoredSettledNative17AliasViews<'_, 'input>, ProviderError> {
        // A failed or dropped pass keeps its partial state. Only finish can
        // authorize replay, whose views must match the original admitted data.
        if self.pass_in_progress {
            return Err(invalid());
        }
        let fields = Fields::array(self.input)?;
        self.pass_number = self.pass_number.checked_add(1).ok_or_else(invalid)?;
        self.pass_in_progress = true;
        Ok(RestoredSettledNative17AliasViews {
            fields,
            summaries: &mut self.summaries[..self.groups],
            remaining: self.rows,
            comparisons: 0,
            failed: false,
            pass_in_progress: &mut self.pass_in_progress,
            pass_number: self.pass_number,
        })
    }
}

/// Checks repeated shared views against each admitted first group.
pub struct RestoredSettledNative17AliasViews<'scratch, 'input> {
    fields: Fields<'input>,
    summaries: &'scratch mut [RestoredSettledNative17AliasSummary],
    remaining: usize,
    comparisons: usize,
    failed: bool,
    pass_in_progress: &'scratch mut bool,
    pass_number: usize,
}

impl RestoredSettledNative17AliasViews<'_, '_> {
    /// Conjoins one typed view and its exact capacity-row encoding with its group.
    ///
    /// Digests compare immutable historical data only. They never assert original
    /// allocation identity; that correspondence belongs to the source capture.
    ///
    /// # Errors
    /// Refuses a different kind, layout, view or capacity roster in a repeated
    /// group, an exhausted roster or an invalid checked group index.
    pub fn observe(
        &mut self,
        kind: MetadataSharedKind,
        layout: usize,
        view: &[u8],
        capacity_rows: &[u8],
    ) -> Result<usize, ProviderError> {
        let group = self.begin(kind)?;
        self.finish_group(group, layout, view, capacity_rows)?;
        Ok(group)
    }

    /// Consumes a role edge to an already completed, layout-matching full view.
    ///
    /// This records historical group identity only. The enclosing typed graph
    /// must compare the returned group with its separately defined role root.
    ///
    /// # Errors
    /// Refuses unknown, forward, unfinished, wrong-kind or wrong-layout groups.
    pub(crate) fn reference(
        &mut self,
        kind: MetadataSharedKind,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        let result = self.reference_group(kind, layout);
        self.failed |= result.is_err();
        result
    }

    fn reference_group(
        &mut self,
        kind: MetadataSharedKind,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        let group = self.begin(kind)?;
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if summary.view_digest.is_none()
            || summary.layout != layout
            || summary.definition_pass != self.pass_number
        {
            return Err(invalid());
        }
        summary.in_progress = false;
        Ok(group)
    }

    /// Checks a role-only backedge to this exact enclosing native Boot.
    ///
    /// The concrete Boot reader supplies its actual begun root group. This does
    /// not begin another payload traversal or complete the parent: its final
    /// full-view/capacity digest and whole-pass finish remain mandatory.
    pub(crate) fn native_boot_parent_reference(
        &mut self,
        expected_group: usize,
        layout: usize,
    ) -> Result<usize, ProviderError> {
        let result = (|| {
            if self.failed || self.remaining == 0 || layout == 0 {
                return Err(invalid());
            }
            let field = self.fields.next()?.ok_or_else(invalid)?;
            let (kind, group) = row(field)?;
            if kind != MetadataSharedKind::NativeBoot || group != expected_group {
                return Err(invalid());
            }
            let parent = self.summaries.get_mut(group).ok_or_else(invalid)?;
            if parent.kind != Some(MetadataSharedKind::NativeBoot)
                || !parent.in_progress
                || (parent.layout != 0 && parent.layout != layout)
            {
                return Err(invalid());
            }
            // A first-pass role pins the layout before the enclosing full-view
            // finish. Later roles and the eventual definition must agree.
            parent.layout = layout;
            self.remaining -= 1;
            Ok(group)
        })();
        self.failed |= result.is_err();
        result
    }

    pub(crate) fn begin(&mut self, kind: MetadataSharedKind) -> Result<usize, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.begin_row(kind);
        self.failed |= result.is_err();
        result
    }

    fn begin_row(&mut self, kind: MetadataSharedKind) -> Result<usize, ProviderError> {
        let field = self.fields.next()?.ok_or_else(invalid)?;
        let (stored_kind, group) = row(field)?;
        if stored_kind != kind || self.remaining == 0 {
            return Err(invalid());
        }
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if summary.in_progress {
            // Full payload traversal cannot recursively enter its current
            // definition. The explicit Boot parent role is checked separately.
            return Err(invalid());
        }
        summary.in_progress = true;
        self.remaining -= 1;
        Ok(group)
    }

    pub(crate) fn finish_group(
        &mut self,
        group: usize,
        layout: usize,
        view: &[u8],
        capacity_rows: &[u8],
    ) -> Result<(), ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.finish_group_view(group, layout, view, capacity_rows);
        self.failed |= result.is_err();
        result
    }

    fn finish_group_view(
        &mut self,
        group: usize,
        layout: usize,
        view: &[u8],
        capacity_rows: &[u8],
    ) -> Result<(), ProviderError> {
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if !summary.in_progress || (summary.layout != 0 && summary.layout != layout) {
            return Err(invalid());
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"source-private.historical-shared-view/17");
        hash.update(&layout.to_le_bytes());
        hash.update(&view.len().to_le_bytes());
        hash.update(view);
        hash.update(capacity_rows);
        let digest = *hash.finalize().as_bytes();
        if let Some(first) = summary.view_digest {
            if first != digest || summary.layout != layout {
                return Err(invalid());
            }
        } else {
            summary.layout = layout;
            summary.view_digest = Some(digest);
        }
        summary.definition_pass = self.pass_number;
        summary.in_progress = false;
        Ok(())
    }

    pub(crate) fn observe_content(
        &mut self,
        edge: crate::client::compact_cursor::ContentGroupEdge,
        layout: usize,
        digest: &[u8],
        capacity_rows: &[u8],
    ) -> Result<usize, ProviderError> {
        let result = self.observe_content_group(edge, layout, digest, capacity_rows);
        self.failed |= result.is_err();
        result
    }

    fn observe_content_group(
        &mut self,
        edge: crate::client::compact_cursor::ContentGroupEdge,
        layout: usize,
        digest: &[u8],
        capacity_rows: &[u8],
    ) -> Result<usize, ProviderError> {
        let group = self.begin(MetadataSharedKind::ContentBytes)?;
        let identity = (edge.kind, edge.index);
        // The content-eight first-group edge and outer alias edge must describe
        // the same graph, including equal-but-distinct first allocations.
        for (index, summary) in self.summaries.iter().enumerate() {
            self.comparisons = self.comparisons.checked_add(1).ok_or_else(invalid)?;
            if self.comparisons > 64 * 1024 * 1024 {
                return Err(invalid());
            }
            if index != group && summary.content_edge == Some(identity) {
                return Err(invalid());
            }
        }
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if summary.content_edge.is_some_and(|first| first != identity) {
            return Err(invalid());
        }
        // Content-edge failures leave the consumed group unfinished, just as
        // a mismatching digest does. A caller cannot finish after ignoring one.
        self.finish_group(group, layout, digest, capacity_rows)?;
        self.summaries
            .get_mut(group)
            .ok_or_else(invalid)?
            .content_edge = Some(identity);
        Ok(group)
    }

    /// Requires complete consumption before any reconstructed graph is accepted.
    ///
    /// # Errors
    /// Refuses unvisited, trailing or unfinished shared rows, including a group
    /// whose observed view failed validation after consuming its roster row.
    pub fn finish(mut self) -> Result<(), ProviderError> {
        if self.failed
            || self.remaining != 0
            || self.fields.next()?.is_some()
            || self.summaries.iter().any(|summary| summary.in_progress)
        {
            return Err(invalid());
        }
        *self.pass_in_progress = false;
        Ok(())
    }
}

/// Reads a stored embedded recorder row without consuming the enclosing ledger.
///
/// This DATA parser creates no shared group, original identity or live right.
///
/// # Errors
/// Refuses an unknown explicit17 category, malformed index or extra fields.
pub(crate) fn read_alias_row17_data(
    input: &[u8],
) -> Result<(MetadataSharedKind, usize), ProviderError> {
    row(input)
}

fn row(input: &[u8]) -> Result<(MetadataSharedKind, usize), ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = match plain_string(fields.next()?.ok_or_else(invalid)?)? {
        "historical-import-policy" => MetadataSharedKind::HistoricalImportPolicy,
        "historical-import-boot" => MetadataSharedKind::HistoricalImportBoot,
        "historical-import-frames" => MetadataSharedKind::HistoricalImportFrames,
        "historical-import-blob-ledger" => MetadataSharedKind::HistoricalImportBlobLedger,
        "historical-import-extensions" => MetadataSharedKind::HistoricalImportExtensions,
        "native_restore_response" => MetadataSharedKind::NativeRestoreResponse,
        "native-restored-physical-hold" => MetadataSharedKind::NativeRestoredPhysicalHold,
        "native-restore-commit-attempt" => MetadataSharedKind::NativeRestoreCommitAttempt,
        "native-restore-input-custody" => MetadataSharedKind::NativeRestoreInputCustody,
        "native-restoration-observation-attempt" => {
            MetadataSharedKind::NativeRestorationObservationAttempt
        }
        "native-restored-suffix-observe-attempt" => {
            MetadataSharedKind::NativeRestoredSuffixObservationAttempt
        }
        "native-restored-producer-attempt" => MetadataSharedKind::NativeRestoredProducerAttempt,
        "native-restored-settled-action-attempt" => {
            MetadataSharedKind::NativeRestoredSettledActionAttempt
        }
        "native-fresh-report-attempt" => MetadataSharedKind::NativeFreshReportAttempt,
        "native-restore-prepare-attempt" => MetadataSharedKind::NativeRestorePrepareAttempt,
        "native-restoration-activation-attempt" => {
            MetadataSharedKind::NativeRestorationActivationAttempt
        }
        "native-restoration-upload-attempt" => MetadataSharedKind::NativeRestorationUploadAttempt,
        "protocol-owner" => MetadataSharedKind::ProtocolOwner,
        "registrar-epoch" => MetadataSharedKind::RegistrarEpoch,
        "registrar-gate" => MetadataSharedKind::RegistrarGate,
        "selected-extensions" => MetadataSharedKind::SelectedExtensions,
        "codec" => MetadataSharedKind::Codec,
        "native-policy" => MetadataSharedKind::NativePolicy,
        "hello-bank" => MetadataSharedKind::HelloBank,
        "content-bytes" => MetadataSharedKind::ContentBytes,
        "frame-bank" => MetadataSharedKind::FrameBank,
        "native-boot" => MetadataSharedKind::NativeBoot,
        "private-bootstrap-bank" => MetadataSharedKind::PrivateBootstrapBank,
        "installed-registry" => MetadataSharedKind::InstalledRegistry,
        "native-supervisor" => MetadataSharedKind::NativeSupervisor,
        "native-control-identity" => MetadataSharedKind::NativeControlIdentity,
        "blob-ledger" => MetadataSharedKind::BlobLedger,
        "host-supervisor" => MetadataSharedKind::HostSupervisor,
        "operational-deadline" => MetadataSharedKind::OperationalDeadline,
        "archived-mapping" => MetadataSharedKind::ArchivedMapping,
        _ => return Err(invalid()),
    };
    let group =
        crate::protocol_snapshot::owned11::typed::unsigned(fields.next()?.ok_or_else(invalid)?)?;
    fields.finish()?;
    Ok((kind, usize::try_from(group).map_err(|_| invalid())?))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "explicit17 historical alias fixture observations"
)]
mod tests {
    use super::*;

    #[test]
    fn aliases_require_equal_full_views_but_equal_distinct_groups_remain_distinct() {
        let mut scratch = [RestoredSettledNative17AliasSummary::default(); 3];
        let mut plan = ValidatedRestoredSettledNative17Aliases::validate(
            br#"[["content-bytes",0],["content-bytes",0],["content-bytes",1]]"#,
            &mut scratch,
            3,
        )
        .unwrap();
        assert_eq!(plan.group_count(), 2);
        let mut views = plan.views().unwrap();
        assert_eq!(
            views
                .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap19")
                .unwrap(),
            0
        );
        assert_eq!(
            views
                .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap19")
                .unwrap(),
            0
        );
        assert_eq!(
            views
                .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap19")
                .unwrap(),
            1
        );
        views.finish().unwrap();
    }

    #[test]
    fn changed_capacity_or_forward_kind_and_unconsumed_rows_refuse() {
        let mut scratch = [RestoredSettledNative17AliasSummary::default(); 2];
        assert!(
            ValidatedRestoredSettledNative17Aliases::validate(br#"[["codec",1]]"#, &mut scratch, 2)
                .is_err()
        );
        let mut distinct = [RestoredSettledNative17AliasSummary::default(); 2];
        assert!(
            ValidatedRestoredSettledNative17Aliases::validate(
                br#"[["codec",0],["hello-bank",0]]"#,
                &mut distinct,
                2
            )
            .is_err()
        );
        let mut scratch = [RestoredSettledNative17AliasSummary::default(); 2];
        let mut plan = ValidatedRestoredSettledNative17Aliases::validate(
            br#"[["content-bytes",0],["content-bytes",0]]"#,
            &mut scratch,
            2,
        )
        .unwrap();
        let mut views = plan.views().unwrap();
        views
            .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap19")
            .unwrap();
        assert!(
            views
                .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap20")
                .is_err()
        );
        assert_eq!(views.remaining, 0);
        assert!(views.summaries[0].in_progress);
        assert!(views.finish().is_err());

        assert!(plan.views().is_err());
    }

    #[test]
    fn unfinished_group_cannot_complete_after_consuming_its_only_row() {
        let mut scratch = [RestoredSettledNative17AliasSummary::default(); 1];
        let mut plan =
            ValidatedRestoredSettledNative17Aliases::validate(br#"[["codec",0]]"#, &mut scratch, 1)
                .unwrap();
        let mut views = plan.views().unwrap();
        assert_eq!(views.begin(MetadataSharedKind::Codec).unwrap(), 0);
        assert_eq!(views.remaining, 0);
        assert!(views.summaries[0].in_progress);
        assert!(views.finish().is_err());
    }
    #[test]
    fn restored_hold_vocabulary_is_distinct_and_failed_group_stays_unfinished() {
        let input = br#"[["native-restored-physical-hold",0],["native-restored-physical-hold",0]]"#;
        let mut old =
            [crate::protocol_snapshot::owned11::aliases::HistoricalAliasSummary::default(); 1];
        assert!(
            crate::protocol_snapshot::owned11::aliases::ValidatedHistoricalAliases::validate(
                input, &mut old, 2,
            )
            .is_err()
        );

        let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
        let mut plan =
            ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 2).unwrap();
        let mut views = plan.views().unwrap();
        views
            .observe(
                MetadataSharedKind::NativeRestoredPhysicalHold,
                48,
                b"same-historical-view",
                b"same-capacities",
            )
            .unwrap();
        assert!(
            views
                .observe(
                    MetadataSharedKind::NativeRestoredPhysicalHold,
                    48,
                    b"changed-view",
                    b"same-capacities"
                )
                .is_err()
        );
        assert!(views.finish().is_err());
        drop(plan);
        assert!(
            ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 2).is_err()
        );
    }
}

/// Names the actual preadmitted alias summary and complete borrowed view headers.
pub const fn restored_settled_native17_alias_counter_scratch_data() -> usize {
    std::mem::size_of::<RestoredSettledNative17AliasSummary>()
        + std::mem::size_of::<ValidatedRestoredSettledNative17Aliases<'static, 'static>>()
        + std::mem::size_of::<RestoredSettledNative17AliasViews<'static, 'static>>()
        + std::mem::size_of::<Fields<'static>>()
        + std::mem::size_of::<(MetadataSharedKind, usize)>()
        + std::mem::size_of::<Result<(MetadataSharedKind, usize), ProviderError>>()
        + std::mem::size_of::<blake3::Hasher>()
        + std::mem::size_of::<blake3::Hash>()
        + std::mem::size_of::<[u8; 32]>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
        + std::mem::size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod native_boot_parent_tests {
    use super::*;

    #[test]
    fn exact_enclosing_boot_role_preserves_unfinished_parent_until_full_finish()
    -> Result<(), ProviderError> {
        let rows = br#"[["native-boot",0],["native-boot",0]]"#;
        let mut summaries = [RestoredSettledNative17AliasSummary::default()];
        let mut plan = ValidatedRestoredSettledNative17Aliases::validate(rows, &mut summaries, 2)?;
        for _ in 0..2 {
            let mut views = plan.views()?;
            let root = views.begin(MetadataSharedKind::NativeBoot)?;
            assert_eq!(views.native_boot_parent_reference(root, 128)?, root);
            views.finish_group(
                root,
                128,
                b"complete-actual-boot-body",
                b"actual-capacities",
            )?;
            views.finish()?;
        }
        Ok(())
    }

    #[test]
    fn foreign_parent_role_or_different_final_layout_poison_the_same_pass()
    -> Result<(), ProviderError> {
        let rows = br#"[["native-boot",0],["native-boot",0]]"#;
        let mut summaries = [RestoredSettledNative17AliasSummary::default()];
        let mut plan = ValidatedRestoredSettledNative17Aliases::validate(rows, &mut summaries, 2)?;
        {
            let mut views = plan.views()?;
            let root = views.begin(MetadataSharedKind::NativeBoot)?;
            assert!(views.native_boot_parent_reference(root + 1, 128).is_err());
            assert!(views.finish_group(root, 128, b"body", b"rows").is_err());
            assert!(views.finish().is_err());
        }
        assert!(plan.views().is_err());

        let mut summaries = [RestoredSettledNative17AliasSummary::default()];
        let mut plan = ValidatedRestoredSettledNative17Aliases::validate(rows, &mut summaries, 2)?;
        let mut views = plan.views()?;
        let root = views.begin(MetadataSharedKind::NativeBoot)?;
        views.native_boot_parent_reference(root, 128)?;
        assert!(views.finish_group(root, 129, b"body", b"rows").is_err());
        assert!(views.finish().is_err());
        Ok(())
    }
}
