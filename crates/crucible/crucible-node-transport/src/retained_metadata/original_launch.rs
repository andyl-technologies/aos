//! Observes the six original launch views required by fresh derivation.
//!
//! These are actual capacity records, not decoded-content estimates or authority.
//! Partial observations stay visible after the first error. The owning parent
//! separately retains and authenticates the immutable original occurrence.

use super::*;
use crate::reference_packet::service::{
    PacketConnectedSourceProgram, PacketNative5SourceLaunch,
    capture_allocation::PacketNative5CaptureAllocationSelection,
};

/// Retains partial or complete observations of the closed original launch views.
///
/// Every record is the existing fourteen-field metadata type. This type has no
/// wire implementation, Source permission or original-owner identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OriginalLaunchMetadataObservation {
    selection: Option<RetainedProtocolMetadataFacts>,
    provider: Option<RetainedProtocolMetadataFacts>,
    realization: Option<RetainedProtocolMetadataFacts>,
    program_definition: Option<RetainedProtocolMetadataFacts>,
    hello_guarantees: Option<RetainedProtocolMetadataFacts>,
    report_owner_binding: Option<RetainedProtocolMetadataFacts>,
    started: bool,
    complete: bool,
}

impl OriginalLaunchMetadataObservation {
    /// Creates an empty observation with no fabricated successful record.
    pub const fn empty() -> Self {
        Self {
            selection: None,
            provider: None,
            realization: None,
            program_definition: None,
            hello_guarantees: None,
            report_owner_binding: None,
            started: false,
            complete: false,
        }
    }

    /// Visits the actual original views once, retaining each successful prefix.
    ///
    /// The caller first admits [`Self::counter_scratch_data`] under its real
    /// deployment. A non-singleton optional roster remains null; this never
    /// authenticates that roster or suppresses its later original guard.
    ///
    /// # Errors
    /// Refuses a repeated attempt or the first actual typed traversal error.
    pub fn observe_into(
        &mut self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(observation_refused());
        }
        self.started = true;
        self.selection = Some(observe(&launch.selection)?);
        self.provider = Some(observe(&launch.selection.provider)?);
        self.realization = Some(observe(&launch.selection.realization)?);
        self.program_definition = Some(match &launch.program {
            PacketConnectedSourceProgram::Producer { program } => observe(program)?,
            PacketConnectedSourceProgram::Reactive { program } => observe(program)?,
        });
        self.hello_guarantees = match launch.selection.realization.bindings.as_slice() {
            [binding] => Some(observe(&binding.compatibility.guarantees_ref)?),
            _ => None,
        };
        self.report_owner_binding = if launch.capture_allocation_selection
            == Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            match launch.selection.realization.owner_bindings.as_slice() {
                [owner_binding] => Some(observe(owner_binding)?),
                _ => None,
            }
        } else {
            None
        };
        self.complete = true;
        Ok(())
    }

    /// Compares every record field and optional disposition with a fresh walk.
    ///
    /// The caller supplies its retained original; matching numeric facts alone
    /// cannot establish original identity. This performs no query hoisting in
    /// the ordinary native consumers.
    ///
    /// # Errors
    /// Refuses an incomplete record, actual traversal failure or any difference.
    pub fn remeasure_data(&self, launch: &PacketNative5SourceLaunch) -> Result<(), ProviderError> {
        if !self.complete {
            return Err(observation_refused());
        }
        let mut current = Self::empty();
        current.observe_into(launch)?;
        if *self != current {
            return Err(observation_refused());
        }
        Ok(())
    }

    /// Reports whether every required view was actually observed successfully.
    pub const fn is_complete_data(&self) -> bool {
        self.complete
    }

    /// Borrows the actual complete source-selection record, if reached.
    pub const fn selection_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.selection.as_ref()
    }

    /// Borrows the actual provider record, if reached.
    pub const fn provider_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.provider.as_ref()
    }

    /// Borrows the actual realization record, if reached.
    pub const fn realization_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.realization.as_ref()
    }

    /// Borrows the actual selected producer/reactive definition record, if reached.
    pub const fn program_definition_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.program_definition.as_ref()
    }

    /// Borrows guarantees exactly when the observed binding roster was singleton.
    pub const fn hello_guarantees_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.hello_guarantees.as_ref()
    }

    /// Borrows the selected original-report singleton owner-binding record.
    pub const fn report_owner_binding_data(&self) -> Option<&RetainedProtocolMetadataFacts> {
        self.report_owner_binding.as_ref()
    }

    /// Counts fixed fields in the retained observation, including failed prefixes.
    ///
    /// Stored numeric facts are history. Their recorded capacities are never
    /// replayed as current owner rows, and this does not remeasure a launch or
    /// establish currentness. The closed field rosters contain no owned buffers.
    pub fn retained_inline_field_visits_data(&self) -> usize {
        let Self {
            selection,
            provider,
            realization,
            program_definition,
            hello_guarantees,
            report_owner_binding,
            started: _,
            complete: _,
        } = self;
        let mut visits = 8;
        for record in [
            selection,
            provider,
            realization,
            program_definition,
            hello_guarantees,
            report_owner_binding,
        ] {
            if let Some(RetainedProtocolMetadataFacts {
                string_capacity_bytes,
                string_banks,
                vector_capacity_bytes,
                vector_banks,
                boxed_value_bytes,
                shared_value_bytes,
                shared_backing_views,
                tree_containers,
                tree_entries,
                maximum_tree_key_value_bytes,
                maximum_tree_entry_alignment,
                maximum_shared_value_alignment,
                observed_nodes,
                capacity_records,
            }) = record
            {
                let fields: [&usize; 14] = [
                    string_capacity_bytes,
                    string_banks,
                    vector_capacity_bytes,
                    vector_banks,
                    boxed_value_bytes,
                    shared_value_bytes,
                    shared_backing_views,
                    tree_containers,
                    tree_entries,
                    maximum_tree_key_value_bytes,
                    maximum_tree_entry_alignment,
                    maximum_shared_value_alignment,
                    observed_nodes,
                    capacity_records,
                ];
                // Six optional records make this fixed sum at most 92.
                visits += fields.len();
            }
        }
        visits
    }

    /// Names the fixed retained-history field views without launch remeasurement.
    pub fn retained_inline_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<[&Option<RetainedProtocolMetadataFacts>; 6]>()
            + size_of::<std::array::IntoIter<&Option<RetainedProtocolMetadataFacts>, 6>>()
            + size_of::<[&usize; 14]>()
            + size_of::<usize>()
    }

    /// Names the explicit observer, record and same-original remeasurement bank.
    ///
    /// Recursive traversal and opaque runtime retain their defining contracts;
    /// this getter is neither a resource reservation nor a physical-memory sum.
    pub fn counter_scratch_data() -> usize {
        retained_native_launch_counter_scratch_data()
            + size_of::<Self>() * 2
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>() * 2
            + size_of::<&PacketNative5SourceLaunch>() * 2
            + size_of::<&mut Self>()
            + size_of::<&Self>()
            + size_of::<Result<(), ProviderError>>() * 2
    }
}

fn observe<T: ObserveMetadata + ?Sized>(
    value: &T,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    Ok(observer.finish())
}

fn observation_refused() -> ProviderError {
    ProviderError::Correlation("original launch metadata observation")
}

#[cfg(test)]
mod retained_history_tests {
    use super::*;

    #[test]
    fn retained_numeric_history_counts_fields_without_replaying_recorded_capacities() {
        let mut history = OriginalLaunchMetadataObservation::empty();
        assert_eq!(history.retained_inline_field_visits_data(), 8);
        history.started = true;
        history.selection = Some(RetainedProtocolMetadataFacts {
            vector_capacity_bytes: usize::MAX,
            capacity_records: usize::MAX,
            observed_nodes: usize::MAX,
            ..RetainedProtocolMetadataFacts::default()
        });
        let before = history.clone();

        assert_eq!(history.retained_inline_field_visits_data(), 22);
        assert_eq!(history, before);
        assert!(!history.is_complete_data());
        history.provider = history.selection;
        history.realization = history.selection;
        history.program_definition = history.selection;
        history.hello_guarantees = history.selection;
        history.report_owner_binding = history.selection;
        assert_eq!(history.retained_inline_field_visits_data(), 92);
        assert!(!history.is_complete_data());
    }
}
