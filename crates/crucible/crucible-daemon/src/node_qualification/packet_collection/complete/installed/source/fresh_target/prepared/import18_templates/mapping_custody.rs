//! Advances each actual funded Source to its original once-only mapping custody.
//!
//! Formatter, quote and complete constructor admission precede the original
//! Source transition. Every guard loan ends before the whole Prepared census.
//! Mapping custody is independent of complete Recipe, Initial and native phases.

use super::*;

/// Names the fixed retaining and actual once-refusal qualification controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<&mut PreparedCompleteRestoration>()
        + size_of::<&InstalledDeployment>()
        + size_of::<&mut PacketCompleteSemanticSource>()
        + size_of::<usize>() * 4
        + size_of::<[usize; 3]>() * 3
        + size_of::<Result<[usize; 3], RuntimeError>>()
        + size_of::<([u8; 32], crucible_node_format::U64, [u8; 32])>() * 3
        + size_of::<Result<([u8; 32], crucible_node_format::U64, [u8; 32]), RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>() * 4
        + size_of::<Option<usize>>()
        + size_of::<std::array::IntoIter<usize, 3>>()
}

impl PreparedCompleteRestoration {
    /// Admits and retains this member's original Source mapping custody once.
    ///
    /// # Errors
    /// Refuses lost originals, constructor/quote failure, exceeded credit or a
    /// failed same-Source exact/short/spent control; every prefix stays owned.
    pub(super) fn prepare_funded_mapping_lease(
        &mut self,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        self.note_funded_operation_stage("quoting original one-use mapping custody");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_mapping_lease_counter_data(),
        )?;
        let formatter = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_original_launch_identity_prewalk_data()?;
        self.observe_import18_templates_data(formatter)?;
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_mapping_lease_construction_data(usize::MAX)?;
        self.observe_import18_templates_data(row)?;
        let maximum = row.into_iter().try_fold(0usize, |total, axis| {
            total.checked_add(axis).ok_or(RuntimeError::ResourceLimit)
        })?;

        self.note_funded_operation_stage("retaining original one-use mapping custody");
        // This stage retains initial-lifecycle obligations even if the Source
        // transition fails. It does not claim complete Recipe or Initial.
        self.import18_templates.members[selected].stage = Stage::MappingLease;
        let result = (|| {
            let deployment = self
                .import18_templates
                .deployment
                .as_deref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            deployment.note_operation_stage("borrowing original mapping Source");
            let member = &mut self.import18_templates.members[selected];
            let source = member.output.completed_unique_data()?;
            #[cfg(feature = "test-support")]
            {
                deployment.note_operation_stage("checking original mapping one-short refusal");
                authenticate_one_short_before_original(source, row, maximum)?;
            }
            deployment.note_operation_stage("constructing original mapping occurrence");
            source.prepare_native_import18_mapping_lease_into(maximum)?;
            deployment.note_operation_stage("reading original mapping occurrence");
            let data = source.native_import18_original_mapping_lease_data()?;
            member.mapping_lease_data = Some(data);
            #[cfg(feature = "test-support")]
            {
                deployment.note_operation_stage("checking original mapping spent retry");
                authenticate_spent_retry(source, maximum, data)?;
            }
            Ok(())
        })();
        if result.is_ok() {
            self.note_funded_operation_stage("observing retained original mapping custody");
        }
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)
    }
}

/// Checks actual short credit before the original Source attempt is spent.
#[cfg(feature = "test-support")]
fn authenticate_one_short_before_original(
    source: &mut PacketCompleteSemanticSource,
    row: [usize; 3],
    maximum: usize,
) -> Result<(), RuntimeError> {
    let short = maximum.checked_sub(1).ok_or(RuntimeError::ResourceLimit)?;
    if !matches!(
        source.prepare_native_import18_mapping_lease_into(short),
        Err(RuntimeError::ResourceLimit)
    ) || source.native_import18_mapping_lease_construction_data(maximum)? != row
        || source.native_import18_original_mapping_lease_data().is_ok()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

/// Checks that a second real constructor cannot renew the retained occurrence.
#[cfg(feature = "test-support")]
fn authenticate_spent_retry(
    source: &mut PacketCompleteSemanticSource,
    maximum: usize,
    original: ([u8; 32], crucible_node_format::U64, [u8; 32]),
) -> Result<(), RuntimeError> {
    if !matches!(
        source.prepare_native_import18_mapping_lease_into(maximum),
        Err(RuntimeError::DuplicateOperation)
    ) || source.native_import18_original_mapping_lease_data()? != original
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}
