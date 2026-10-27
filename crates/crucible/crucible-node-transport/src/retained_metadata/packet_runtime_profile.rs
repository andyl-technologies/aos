//! Bounds visits to the closed packet runtime's independently growing owners.
//!
//! The original controller supplies actual frame, journal and content limits.
//! Installing these scalar facts delegates no visits until a known mutable
//! owner selects its population. Legacy history retains the ordinary budget.

use super::{MetadataObserver, ProviderError, overflow};

/// Selects one defining mutable population; callers cannot supply a work limit.
#[derive(Clone, Copy)]
pub(crate) enum PacketRuntimeMetadataPopulation {
    Content,
    Correlation,
    Journal,
    Incident,
}

/// Carries occurrence bounds, without funding or ownership authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketRuntimeMetadataProfileData {
    content: usize,
    correlation: usize,
    journal: usize,
    incident: usize,
    tree_containers: usize,
    tree_entries: usize,
}

impl PacketRuntimeMetadataProfileData {
    /// Derives bounds from the original closed runtime's supported limits.
    pub(crate) fn from_original_limits_data(
        frame: usize,
        requests: usize,
        objects: usize,
    ) -> Result<Self, ProviderError> {
        if frame == 0 || frame > 65_536 || requests == 0 || requests > 4096 || objects > 4096 {
            return Err(overflow());
        }

        // Four visits/records per lexical byte covers literal descendants.
        // Envelope root, fields, optional labels and container records add 38.
        let envelope = add(multiply(4, frame)?, 38)?;
        let correlation = add(multiply(3, envelope)?, 12)?;

        // Each of the two suffix maps has at most N entries. A compact entry
        // visits its ID, identity and request/response byte banks, not J bytes.
        // Pending and unexpected frames also retain a typed notification body.
        let journal = add(
            add(multiply(32, requests)?, 8)?,
            add(multiply(3, envelope)?, 16)?,
        )?;

        // Both content maps can each contain O entries; byte payloads are one
        // capacity record each. Containment happens once after fencing and
        // retains at most one outgoing and one incoming envelope.
        let content = add(multiply(32, objects)?, 8)?;
        let incident = add(multiply(2, envelope)?, 32)?;

        // Eight independent literal families can survive: three correlation
        // maps, two incident copies, pending and unexpected Envelopes, and the
        // unexpected typed Notification. Count actual JSON occurrences for tree
        // reporting instead of treating every scalar metadata visit as a map.
        let extent = super::serialization_storage::original_json_value_storage_extent_data(frame)?;
        let tree_containers = add(multiply(8, extent.maximum_value_nodes)?, 4)?;
        let tree_entries = add(
            multiply(8, extent.maximum_object_members)?,
            add(multiply(2, requests)?, multiply(2, objects)?)?,
        )?;
        let profile = Self {
            content,
            correlation,
            journal,
            incident,
            tree_containers,
            tree_entries,
        };
        profile.maximum_future_rows_data()?;
        Ok(profile)
    }

    fn maximum_work_data(self, population: PacketRuntimeMetadataPopulation) -> usize {
        match population {
            PacketRuntimeMetadataPopulation::Content => self.content,
            PacketRuntimeMetadataPopulation::Correlation => self.correlation,
            PacketRuntimeMetadataPopulation::Journal => self.journal,
            PacketRuntimeMetadataPopulation::Incident => self.incident,
        }
    }

    /// Bounds independently retained tree containers and entries for reporting.
    pub(crate) fn maximum_future_tree_population_data(self) -> [usize; 2] {
        [self.tree_containers, self.tree_entries]
    }

    /// Bounds added nodes and capacity records separately for one complete walk.
    pub(crate) fn maximum_future_rows_data(self) -> Result<usize, ProviderError> {
        [self.content, self.correlation, self.journal, self.incident]
            .into_iter()
            .try_fold(0, add)
    }
}

impl MetadataObserver<'_> {
    /// Names actual profile, population, scope restoration and quote controls.
    pub(crate) fn packet_runtime_metadata_profile_counter_scratch_data() -> usize {
        use std::mem::size_of;

        Self::scoped_population_metadata_counter_scratch_data()
            + super::serialization_storage::original_json_value_storage_extent_counter_scratch_data(
            )
            + size_of::<super::serialization_storage::OriginalJsonValueStorageExtentData>()
            + size_of::<
                Result<
                    super::serialization_storage::OriginalJsonValueStorageExtentData,
                    ProviderError,
                >,
            >()
            + 2 * size_of::<PacketRuntimeMetadataProfileData>()
            + size_of::<Option<PacketRuntimeMetadataProfileData>>()
            + size_of::<Result<PacketRuntimeMetadataProfileData, ProviderError>>()
            + size_of::<PacketRuntimeMetadataPopulation>()
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<Result<usize, ProviderError>>()
            + 8 * size_of::<usize>()
    }

    /// Installs actual owner facts without increasing ordinary traversal credit.
    pub(crate) fn with_packet_runtime_owner_data(
        &mut self,
        profile: PacketRuntimeMetadataProfileData,
        observe: impl FnOnce(&mut Self) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let previous = self.packet_runtime.replace(profile);
        let result = observe(self);
        self.packet_runtime = previous;
        result
    }

    /// Charges only the selected mutable owner's independently bounded work.
    pub(crate) fn with_packet_runtime_population_data(
        &mut self,
        population: PacketRuntimeMetadataPopulation,
        observe: impl FnOnce(&mut Self) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        match self.packet_runtime {
            // The strict wire parser permits 64 literal levels; the Value root
            // contributes one additional observer activation.
            Some(profile) => self.with_scoped_population_metadata_data(
                65,
                profile.maximum_work_data(population),
                observe,
            ),
            None => observe(self),
        }
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(overflow)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn owner_installation_keeps_unselected_legacy_work_at_ordinary_limit() {
        let profile =
            PacketRuntimeMetadataProfileData::from_original_limits_data(65_536, 4096, 4096)
                .unwrap();
        let value = Value::Array(vec![Value::Null; 131_072]);
        let mut observer = MetadataObserver::new();

        assert!(
            observer
                .with_packet_runtime_owner_data(profile, |observer| { observer.observe(&value) })
                .is_err()
        );
        assert!(observer.packet_runtime.is_none());
        assert_eq!(observer.json_depth_limit, 64);
        assert!(observer.facts.observed_nodes > 131_072);
    }

    #[test]
    fn dense_children_restore_scopes_and_preserve_refused_partial_facts() {
        let profile =
            PacketRuntimeMetadataProfileData::from_original_limits_data(65_536, 8, 8).unwrap();
        let value = Value::Array(vec![Value::Array(vec![Value::Null]); 15_800]);
        let mut observer = MetadataObserver::new();

        let result = observer.with_packet_runtime_owner_data(profile, |observer| {
            for population in [
                PacketRuntimeMetadataPopulation::Correlation,
                PacketRuntimeMetadataPopulation::Journal,
                PacketRuntimeMetadataPopulation::Incident,
            ] {
                observer.with_packet_runtime_population_data(population, |observer| {
                    observer.observe(&value)
                })?;
            }
            observer.with_packet_runtime_population_data(
                PacketRuntimeMetadataPopulation::Content,
                |observer| observer.observe(&value),
            )
        });

        assert!(result.is_err());
        let partial = observer.facts.observed_nodes;
        assert!(partial > 131_072);
        assert!(observer.packet_runtime.is_none());
        assert_eq!(observer.json_depth, 0);
        assert_eq!(observer.json_depth_limit, 64);

        // Refused child visits neither erase partial facts nor refund ordinary
        // history. The unchanged ordinary allowance still permits a small root.
        observer.observe(&Value::Null).unwrap();
        assert_eq!(observer.facts.observed_nodes, partial + 1);
        assert!(
            observer
                .observe(&Value::Array(vec![Value::Null; 131_072]))
                .is_err()
        );
        assert!(observer.facts.observed_nodes > partial + 131_072);
    }

    #[test]
    fn actual_limit_changes_select_only_their_defining_owner_population() {
        let base = PacketRuntimeMetadataProfileData::from_original_limits_data(4096, 8, 8).unwrap();
        let objects =
            PacketRuntimeMetadataProfileData::from_original_limits_data(4096, 8, 9).unwrap();
        let requests =
            PacketRuntimeMetadataProfileData::from_original_limits_data(4096, 9, 8).unwrap();
        let frame =
            PacketRuntimeMetadataProfileData::from_original_limits_data(4097, 8, 8).unwrap();

        assert_eq!(objects.content - base.content, 32);
        assert_eq!(objects.journal, base.journal);
        assert_eq!(requests.journal - base.journal, 32);
        assert_eq!(requests.content, base.content);
        assert_eq!(frame.content, base.content);
        assert!(frame.correlation > base.correlation);
        assert!(frame.incident > base.incident);
        assert!(
            frame.maximum_future_rows_data().unwrap() > base.maximum_future_rows_data().unwrap()
        );
        assert!(PacketRuntimeMetadataProfileData::from_original_limits_data(65_537, 8, 8).is_err());
        assert!(
            PacketRuntimeMetadataProfileData::from_original_limits_data(4096, 4097, 8).is_err()
        );
        assert!(
            PacketRuntimeMetadataProfileData::from_original_limits_data(4096, 8, 4097).is_err()
        );
    }

    #[test]
    fn runtime_profile_cannot_enlarge_a_precharged_record_bank() {
        let profile =
            PacketRuntimeMetadataProfileData::from_original_limits_data(65_536, 8, 8).unwrap();
        let mut records = super::super::records::MetadataRecordBank::reserve(2).unwrap();
        let capacity = records.capacity_rows();
        let mut observer = MetadataObserver::recording(&mut records);
        let result = observer.with_packet_runtime_owner_data(profile, |observer| {
            observer.with_packet_runtime_population_data(
                PacketRuntimeMetadataPopulation::Correlation,
                |observer| observer.observe(&serde_json::json!([[], [], []])),
            )
        });

        assert!(result.is_err());
        assert!(observer.facts.capacity_records > 2);
        assert!(observer.packet_runtime.is_none());
        assert_eq!(observer.json_depth_limit, 64);
        let _facts = observer.finish();
        assert_eq!(records.capacity_rows(), capacity);
        assert!(super::super::records::MetadataRecordBank::reserve(131_073).is_err());
    }
}
