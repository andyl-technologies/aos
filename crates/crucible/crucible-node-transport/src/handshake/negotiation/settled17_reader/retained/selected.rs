//! Retains concrete selected-extension staging without resetting the source cursor.

use super::*;
use crucible_node_format::ExtensionSelection;
use std::sync::Arc;

type SelectionAttempt = <ExtensionSelection as Native17Build>::Attempt;

/// Keeps staging values and every initialized pending child in the once owner.
#[derive(Default)]
pub(super) struct SelectedExtensions17ReadAttempt {
    started: bool,
    completed: Option<Option<Arc<[ExtensionSelection]>>>,
    pub(super) values: Vec<ExtensionSelection>,
    pub(super) children: Vec<SelectionAttempt>,
}

impl SelectedExtensions17ReadAttempt {
    pub(super) fn read_into_data(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 selected slice already attempted",
            ));
        }
        self.started = true;
        if input == b"null" {
            self.completed = Some(None);
            return Ok(());
        }
        let (start, extent, count, group, target_children) = begin(input, ledger)?;
        let cached = ledger
            .selected_groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(Option::as_ref)
            .is_some();
        if cached {
            validate_children(input, count, ledger, target_children)?;
        } else {
            // The transient values bank is priced independently from the final
            // Arc. The retained child-header bank is part of the target plan.
            if target_children {
                ledger.native17_target_vector_data::<SelectionAttempt>(count)?;
            }
            self.values
                .try_reserve_exact(count)
                .map_err(|_| capacity())?;
            if self.values.capacity() != count {
                return Err(capacity());
            }
            self.children
                .try_reserve_exact(count)
                .map_err(|_| capacity())?;
            if size_of::<SelectionAttempt>() != 0 && self.children.capacity() != count {
                return Err(capacity());
            }
            let mut fields = Fields::array(input)?;
            while let Some(item) = fields.next_value()? {
                if self.children.len() == count {
                    return Err(invalid());
                }
                self.children.push(Default::default());
                let child = self.children.last_mut().ok_or_else(invalid)?;
                ExtensionSelection::read_into_data(item, ledger, child)?;
                self.values
                    .push(ExtensionSelection::take_output_data(child).ok_or_else(invalid)?);
            }
            fields.finish()?;
            if self.values.len() != count {
                return Err(invalid());
            }
        }
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, extent, input, rows)?;
        let slot = ledger
            .selected_groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
            .ok_or_else(invalid)?;
        if let Some(existing) = slot {
            self.completed = Some(Some(existing.clone()));
        } else {
            // All fallible grammar, accounting and cache-slot checks precede
            // this move. Exact capacity makes into_boxed_slice a pure transfer.
            let values: Arc<[ExtensionSelection]> =
                Arc::from(std::mem::take(&mut self.values).into_boxed_slice());
            self.completed = Some(Some(values.clone()));
            *slot = Some(values);
        }
        Ok(())
    }

    pub(super) fn preflight_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        if input == b"null" {
            return Ok(());
        }
        let (start, extent, count, group, target_children) = begin(input, ledger)?;
        if target_children {
            ledger.native17_target_vector_data::<SelectionAttempt>(count)?;
        }
        validate_children(input, count, ledger, target_children)?;
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, extent, input, rows)
    }

    pub(super) fn output_data(&self) -> Option<&Option<Arc<[ExtensionSelection]>>> {
        self.completed.as_ref()
    }

    pub(super) fn take_output_data(&mut self) -> Option<Option<Arc<[ExtensionSelection]>>> {
        self.completed.take()
    }

    pub(super) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<ExtensionSelection>(self.values.capacity())?;
        for value in &self.values {
            ExtensionSelection::observe_output_data(value, observer)?;
        }
        observer.vector::<SelectionAttempt>(self.children.capacity())?;
        for child in &self.children {
            ExtensionSelection::observe_attempt_data(child, observer)?;
        }
        // The final Arc is counted in the outer selected_groups cache once.
        Ok(())
    }
}

fn begin(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(usize, usize, usize, usize, bool), ProviderError> {
    // Fields validates the complete borrowed array without allocating a DOM.
    Fields::array(input)?;
    let start = ledger.rows.encoded_position();
    let extent = ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<ExtensionSelection>(),
    )?;
    let element = size_of::<ExtensionSelection>();
    if element == 0 || extent % element != 0 {
        return Err(invalid());
    }
    let count = extent / element;
    if count > 4096 {
        return Err(invalid());
    }
    ledger.selected_slice_staging_bytes = ledger.selected_slice_staging_bytes.max(extent);
    let group = ledger.shared_begin(MetadataSharedKind::SelectedExtensions)?;
    let target_children =
        ledger.native17_target_shared_slice_data::<ExtensionSelection>(group, count)?;
    if target_children {
        // The fallible child walk retains this independent values bank before
        // promotion to the separately priced shared slice.
        ledger.native17_target_vector_data::<ExtensionSelection>(count)?;
    }
    Ok((start, extent, count, group, target_children))
}

fn validate_children(
    input: &[u8],
    count: usize,
    ledger: &mut Ledger<'_, '_, '_>,
    target_children: bool,
) -> Result<(), ProviderError> {
    // Repeated views still consume their complete source rows and compare the
    // full digest. Only the already-owned target allocation is discounted.
    let pause = if !target_children {
        Some(ledger.suspend_native17_targets_data()?)
    } else {
        None
    };
    let result = (|| {
        let mut fields = Fields::array(input)?;
        let mut actual = 0usize;
        while let Some(item) = fields.next_value()? {
            actual = actual
                .checked_add(1)
                .filter(|actual| *actual <= count)
                .ok_or_else(invalid)?;
            ExtensionSelection::preflight_data(item, ledger)?;
        }
        fields.finish()?;
        if actual != count {
            return Err(invalid());
        }
        Ok(())
    })();
    if let Some(pause) = pause {
        ledger.resume_native17_targets_data(pause)?;
    }
    result
}

fn capacity() -> ProviderError {
    ProviderError::ResourceExhausted("native17 retained selected-extension staging")
}
