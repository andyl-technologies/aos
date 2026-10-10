//! Retains actual selected codec rows without inferring foreign dependency leaves.

use super::control::{ReaderState, original_id};
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::{
    ProviderError, client::LineageWindowRequests, reference_device::DeviceGrant,
};

const RESERVED_OBJECTS: usize = 96;
const RESERVED_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_OBJECTS: usize = 4096;
const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;

type OriginalRow = (InputPayload, Vec<ContentRef>);

impl ReaderState {
    pub(super) fn preflight_window_evidence(&self) -> Result<(), ProviderError> {
        let count = self.boundary_evidence.len().checked_add(RESERVED_OBJECTS);
        let bytes = self
            .boundary_evidence
            .values()
            .try_fold(RESERVED_BYTES, |total, object| {
                total.checked_add(object.bytes.len())
            });
        let edges = self
            .boundary_dependencies
            .values()
            .try_fold(1024usize, |total, row| total.checked_add(row.len()));
        if edges.is_none_or(|count| count > 65_536)
            || count.is_none_or(|count| count > MAXIMUM_OBJECTS)
            || bytes.is_none_or(|bytes| bytes > MAXIMUM_BYTES)
        {
            return Err(ProviderError::ResourceExhausted(
                "original selected window evidence credit",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_window_evidence(
        &mut self,
        grant: &DeviceGrant,
    ) -> Result<(), ProviderError> {
        let window = self
            .windows
            .get(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original selected window omitted",
            ))?;
        let input = window.original.inputs().ok_or(ProviderError::Correlation(
            "original selected input omitted",
        ))?;
        let input_request = original_id("input", input.stage_operation())?;
        let begin_request = original_id("begin", window.original.token().operation())?;
        let rows = self.guard.with_original_window(
            LineageWindowRequests {
                realization: &self.realization,
                input: &input_request,
                begin: &begin_request,
            },
            |source| {
                let inventory = source.measurement_evidence(80, 1024 * 1024)?;
                let mut rows: Vec<OriginalRow> = Vec::new();
                rows.try_reserve_exact(inventory.objects().len())
                    .map_err(|_| {
                        ProviderError::ResourceExhausted("original selected evidence allocation")
                    })?;
                for object in inventory.objects() {
                    rows.push((
                        InputPayload {
                            reference: object.reference().clone(),
                            bytes: object.bytes().to_vec(),
                        },
                        object.dependencies().to_vec(),
                    ));
                }
                Ok(rows)
            },
        )?;
        self.validate_new_rows(&rows)?;
        // A missing foreign row stays missing. Only actual borrowed selected
        // source rows enter this registry; uploaded bodies do not imply leaves.
        for (object, dependencies) in rows {
            self.runtime
                .boundary_dependencies
                .insert(object.reference.clone(), dependencies);
            self.runtime
                .boundary_evidence
                .insert(object.reference.clone(), object);
        }
        Ok(())
    }

    fn validate_new_rows(&self, rows: &[OriginalRow]) -> Result<(), ProviderError> {
        let mut edges = self
            .boundary_dependencies
            .values()
            .try_fold(0usize, |total, row| total.checked_add(row.len()))
            .ok_or(ProviderError::ResourceExhausted(
                "original selected edge credit",
            ))?;
        let mut count = self.boundary_evidence.len();
        let mut bytes = self
            .boundary_evidence
            .values()
            .try_fold(0usize, |total, object| {
                total.checked_add(object.bytes.len())
            })
            .ok_or(ProviderError::ResourceExhausted(
                "original selected evidence bytes",
            ))?;
        for (object, dependencies) in rows {
            object.reference.verify(&object.bytes)?;
            if object.reference.length != U64::new(object.bytes.len() as u64) {
                return Err(ProviderError::Correlation(
                    "original selected extent changed",
                ));
            }
            if let Some(original) = self.boundary_evidence.get(&object.reference) {
                if original != object
                    || self.boundary_dependencies.get(&object.reference) != Some(dependencies)
                {
                    return Err(ProviderError::Correlation("original selected row changed"));
                }
            } else {
                edges = edges.checked_add(dependencies.len()).ok_or(
                    ProviderError::ResourceExhausted("original selected edge overflow"),
                )?;
                count = count
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted(
                        "original selected evidence count",
                    ))?;
                bytes = bytes.checked_add(object.bytes.len()).ok_or(
                    ProviderError::ResourceExhausted("original selected evidence bytes"),
                )?;
            }
        }
        if count > MAXIMUM_OBJECTS || bytes > MAXIMUM_BYTES || edges > 65_536 {
            return Err(ProviderError::ResourceExhausted(
                "original selected evidence reservation exceeded",
            ));
        }
        Ok(())
    }
}
