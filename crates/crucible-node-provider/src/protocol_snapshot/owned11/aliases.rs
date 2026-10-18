//! Checks local historical shared groups before reconstructing typed owners.
//!
//! Group indices describe aliases inside one archive. They cannot identify an
//! original actor or enroll a live registrar, policy or connection. A caller
//! precharges the summary slice before invoking the complete grammar pass.
//!
//! ```json
//! [["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0]]
//! ```

use super::typed::{Fields, invalid, plain_string};
use crate::ProviderError;
use crate::retained_metadata::aliases::MetadataSharedKind;

/// Stores one admitted first-group summary without retaining process addresses.
#[derive(Clone, Copy, Default)]
pub struct HistoricalAliasSummary {
    kind: Option<MetadataSharedKind>,
    layout: usize,
    view_digest: Option<[u8; 32]>,
    in_progress: bool,
    content_edge: Option<(crate::client::compact_cursor::ContentGroupKind, usize)>,
}

/// Borrows a completely validated local alias roster and precharged summaries.
pub struct ValidatedHistoricalAliases<'input, 'scratch> {
    input: &'input [u8],
    summaries: &'scratch mut [HistoricalAliasSummary],
    rows: usize,
    groups: usize,
}

impl<'input, 'scratch> ValidatedHistoricalAliases<'input, 'scratch> {
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
        summaries: &'scratch mut [HistoricalAliasSummary],
        maximum_rows: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_rows == 0 || maximum_rows > 131072 || summaries.len() > 131072 {
            return Err(invalid());
        }
        summaries.fill(HistoricalAliasSummary::default());
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

    /// Starts a source-order shared-view pass over the same immutable roster.
    pub fn views(&mut self) -> Result<HistoricalAliasViews<'_, 'input>, ProviderError> {
        for summary in self.summaries.iter_mut().take(self.groups) {
            summary.layout = 0;
            summary.view_digest = None;
            summary.in_progress = false;
            summary.content_edge = None;
        }
        Ok(HistoricalAliasViews {
            fields: Fields::array(self.input)?,
            summaries: &mut self.summaries[..self.groups],
            remaining: self.rows,
            comparisons: 0,
        })
    }
}

/// Checks repeated shared views against each admitted first group.
pub struct HistoricalAliasViews<'scratch, 'input> {
    fields: Fields<'input>,
    summaries: &'scratch mut [HistoricalAliasSummary],
    remaining: usize,
    comparisons: usize,
}

impl HistoricalAliasViews<'_, '_> {
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

    pub(crate) fn begin(&mut self, kind: MetadataSharedKind) -> Result<usize, ProviderError> {
        let field = self.fields.next()?.ok_or_else(invalid)?;
        let (stored_kind, group) = row(field)?;
        if stored_kind != kind || self.remaining == 0 {
            return Err(invalid());
        }
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if summary.in_progress {
            // Capturable source graphs have no recursive owning Rc cycle.
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
        let summary = self.summaries.get_mut(group).ok_or_else(invalid)?;
        if !summary.in_progress {
            return Err(invalid());
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"source-private.historical-shared-view/11");
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
        let group = self.observe(
            MetadataSharedKind::ContentBytes,
            layout,
            digest,
            capacity_rows,
        )?;
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
        summary.content_edge = Some(identity);
        Ok(group)
    }

    /// Requires complete consumption before any reconstructed graph is accepted.
    ///
    /// # Errors
    /// Refuses unvisited, trailing or unfinished shared rows, including a group
    /// whose observed view failed validation after consuming its roster row.
    pub fn finish(mut self) -> Result<(), ProviderError> {
        if self.remaining != 0
            || self.fields.next()?.is_some()
            || self.summaries.iter().any(|summary| summary.in_progress)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Counts the exact required first-group bank using this reader's row grammar.
///
/// Repeated group-kind and view equality need the independently funded complete
/// validator. This prewalk checks bounds and first/backward topology only and
/// cannot construct a validated alias owner.
pub(crate) fn required_summary_entries_data(
    input: &[u8],
    maximum_rows: usize,
) -> Result<usize, ProviderError> {
    if maximum_rows == 0 || maximum_rows > 131_072 {
        return Err(invalid());
    }
    let mut fields = Fields::array(input)?;
    let mut rows = 0usize;
    let mut groups = 0usize;
    while let Some(field) = fields.next()? {
        let (_, group) = row(field)?;
        rows = rows.checked_add(1).ok_or_else(invalid)?;
        if rows > maximum_rows || group > groups {
            return Err(invalid());
        }
        if group == groups {
            groups = groups.checked_add(1).ok_or_else(invalid)?;
        }
    }
    fields.finish()?;
    Ok(groups)
}

/// Names the real topology prewalk and complete alias validator fixed views.
pub(crate) fn borrowed_validation_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<ValidatedHistoricalAliases<'static, 'static>>()
        + size_of::<HistoricalAliasViews<'static, 'static>>()
        + size_of::<HistoricalAliasSummary>()
        + size_of::<super::typed::Fields<'static>>() * 2
        + super::typed::Fields::counter_scratch_data()
        + size_of::<&mut [HistoricalAliasSummary]>()
        + size_of::<std::slice::IterMut<'static, HistoricalAliasSummary>>()
        + size_of::<std::iter::Take<std::slice::IterMut<'static, HistoricalAliasSummary>>>()
        + size_of::<std::slice::Iter<'static, HistoricalAliasSummary>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, HistoricalAliasSummary>>>()
        + size_of::<Option<(usize, &'static HistoricalAliasSummary)>>()
        + size_of::<MetadataSharedKind>()
        + size_of::<Result<(MetadataSharedKind, usize), ProviderError>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<usize>() * 4
        + size_of::<[u8; 32]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

fn row(input: &[u8]) -> Result<(MetadataSharedKind, usize), ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = match plain_string(fields.next()?.ok_or_else(invalid)?)? {
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
    let group = super::typed::unsigned(fields.next()?.ok_or_else(invalid)?)?;
    fields.finish()?;
    Ok((kind, usize::try_from(group).map_err(|_| invalid())?))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "historical alias fixture assertions")]
mod tests {
    use super::*;

    #[test]
    fn aliases_require_equal_full_views_but_equal_distinct_groups_remain_distinct() {
        let mut scratch = [HistoricalAliasSummary::default(); 3];
        let mut plan = ValidatedHistoricalAliases::validate(
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
        let mut scratch = [HistoricalAliasSummary::default(); 2];
        assert!(
            ValidatedHistoricalAliases::validate(br#"[["codec",1]]"#, &mut scratch, 2).is_err()
        );
        assert!(
            ValidatedHistoricalAliases::validate(
                br#"[["codec",0],["hello-bank",0]]"#,
                &mut scratch,
                2
            )
            .is_err()
        );
        let mut plan = ValidatedHistoricalAliases::validate(
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

        let mut views = plan.views().unwrap();
        views
            .observe(MetadataSharedKind::ContentBytes, 24, b"empty", b"cap19")
            .unwrap();
        assert_eq!(views.remaining, 1);
        assert!(views.finish().is_err());
    }

    #[test]
    fn unfinished_group_cannot_complete_after_consuming_its_only_row() {
        let mut scratch = [HistoricalAliasSummary::default(); 1];
        let mut plan =
            ValidatedHistoricalAliases::validate(br#"[["codec",0]]"#, &mut scratch, 1).unwrap();
        let mut views = plan.views().unwrap();
        assert_eq!(views.begin(MetadataSharedKind::Codec).unwrap(), 0);
        assert_eq!(views.remaining, 0);
        assert!(views.summaries[0].in_progress);
        assert!(views.finish().is_err());
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalAliasSummary,
    kind,
    layout,
    view_digest,
    in_progress,
    content_edge
);

#[path = "aliases/current17.rs"]
mod current17;
