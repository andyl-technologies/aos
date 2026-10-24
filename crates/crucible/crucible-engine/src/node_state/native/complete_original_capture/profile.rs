//! Separates the selected preservation facet from historical state codecs.
//!
//! A facet's version identifies its preservation contract. It is not the version
//! of every state format that contract can preserve. Complete original capture
//! admits only the explicit installed packet/Host families below; full schema
//! membership and source-specific cold validation remain independent checks.

use crate::node_contract::NativeStateKey;
use crucible_node_format::BindingCompatibility;

pub(super) fn matches_selected_complete_state_profile(
    key: &NativeStateKey,
    binding: &BindingCompatibility,
) -> bool {
    let selected_version = match (
        key.implementation.as_str(),
        key.profile.as_str(),
        key.schema.id.as_str(),
        key.schema.version,
    ) {
        (
            "source-owned.packet-native/5",
            "source-owned.packet-complete-original-lineage/5",
            "source-owned.packet-native-continuation/11",
            11,
        )
        | (
            "source-owned.packet-native/5",
            "source-owned.packet-complete-original-lineage/5",
            "source-owned.packet-native-continuation/13",
            13,
        )
        | (
            "source-owned.packet-native/5",
            "source-owned.packet-complete-original-lineage/5",
            "source-owned.packet-native-continuation/14",
            14,
        ) => 5,
        (
            "source-owned.host-scheduling-owner/2",
            "source-owned.host-scheduling-original-lineage/2",
            "source-owned.host-scheduling-continuation/2",
            2,
        ) => 2,
        _ => return false,
    };

    key.implementation == binding.implementation.implementation_id
        && binding.implementation.formats.contains(&key.schema)
        && binding
            .operating_contract
            .facets
            .iter()
            .any(|facet| facet.id == key.profile && facet.version == selected_version)
}

impl NativeStateKey {
    /// Checks only the explicit complete-state/facet correspondence.
    ///
    /// The owning producer and cold decoder must still authenticate the full
    /// compiled definition and current custody. A positive DATA comparison is
    /// not a preflight loan, snapshot permission or native restoration grant.
    pub(crate) fn matches_selected_complete_state_profile_data(
        &self,
        binding: &BindingCompatibility,
    ) -> bool {
        matches_selected_complete_state_profile(self, binding)
    }
}

#[cfg(test)]
mod tests {
    // Synthetic metadata uses the real compiled state-schema constructor. It
    // proves compatibility checks only, not capture or fresh native authority.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_format::{
        Extensions, FacetSelection, Id, ImplementationIdentity, OperatingContract, OperatingMode,
        OwnerRef, SchedulingRole, canonical,
    };

    fn invocation15() -> (NativeStateKey, BindingCompatibility) {
        let reference =
            canonical::content_ref(b"profile correspondence control", "application/json").unwrap();
        let implementation = Id::new("source-owned.packet-native/5").unwrap();
        let profile = Id::new("source-owned.packet-complete-original-lineage/5").unwrap();
        let schema = crucible_node_transport::reference_packet::service::native_snapshot::native_owned14_snapshot_schema().unwrap();
        let facet = FacetSelection {
            id: profile.clone(),
            version: 5,
            configuration_ref: reference.clone(),
            guarantees_ref: reference.clone(),
            extensions: Extensions::new(),
        };
        let owner = OwnerRef {
            id: Id::new("owner").unwrap(),
            participant_ids: vec![Id::new("node").unwrap()],
            state_domain_ids: vec![Id::new("state").unwrap()],
        };
        let binding = BindingCompatibility {
            schema_version: 1,
            node_id: Id::new("node").unwrap(),
            descriptor_hash: reference.hash.clone(),
            implementation: ImplementationIdentity {
                schema_version: 1,
                implementation_id: implementation.clone(),
                artifacts: vec![],
                model_definitions: vec![reference.clone()],
                formats: vec![schema.clone()],
                extensions: Extensions::new(),
            },
            profile_ref: reference.clone(),
            configuration_ref: reference.clone(),
            operating_contract: OperatingContract {
                schema_version: 1,
                mode: OperatingMode::Exact,
                scheduling_role: SchedulingRole::Active,
                ordering_profile: "superdense-v1".into(),
                policy_ref: reference.clone(),
                resolution_ps: Some(1.into()),
                phase_ps: Some(0.into()),
                facets: vec![facet],
                extensions: Extensions::new(),
            },
            execution_owner: owner.clone(),
            capture_owner: owner,
            capabilities_ref: reference.clone(),
            guarantees_ref: reference.clone(),
            qualification_refs: vec![reference],
            extensions: Extensions::new(),
        };
        (
            NativeStateKey {
                implementation,
                profile,
                schema,
            },
            binding,
        )
    }

    #[test]
    fn genuine_invocation15_schema_keeps_preservation_facet5() {
        let (key, mut binding) = invocation15();

        assert_eq!(key.schema.version, 14);
        assert_eq!(binding.operating_contract.facets[0].version, 5);
        assert!(key.matches_selected_complete_state_profile_data(&binding));

        binding.operating_contract.facets[0].version = key.schema.version;
        assert!(!key.matches_selected_complete_state_profile_data(&binding));
    }

    #[test]
    fn complete_legacy_families_use_their_actual_preservation_version() {
        use crucible_node_transport::reference_packet::service::native_snapshot::{
            native_owned11_snapshot_schema, native_owned13_snapshot_schema,
        };

        for schema in [
            native_owned11_snapshot_schema().unwrap(),
            native_owned13_snapshot_schema().unwrap(),
        ] {
            let (mut key, mut binding) = invocation15();
            key.schema = schema.clone();
            binding.implementation.formats = vec![schema];

            assert!(matches_selected_complete_state_profile(&key, &binding));
        }

        let (mut key, mut binding) = invocation15();
        key.implementation = Id::new("source-owned.host-scheduling-owner/2").unwrap();
        key.profile = Id::new("source-owned.host-scheduling-original-lineage/2").unwrap();
        key.schema = crate::node_contract::host_scheduling_complete_continuation_schema().unwrap();
        binding.implementation.implementation_id = key.implementation.clone();
        binding.implementation.formats = vec![key.schema.clone()];
        binding.operating_contract.facets[0].id = key.profile.clone();
        binding.operating_contract.facets[0].version = 2;

        assert!(matches_selected_complete_state_profile(&key, &binding));
    }

    #[test]
    fn complete_profile_correspondence_refuses_substituted_selected_identity() {
        for changed in 0..9 {
            let (mut key, mut binding) = invocation15();
            match changed {
                0 => key.implementation = Id::new("foreign").unwrap(),
                1 => key.profile = Id::new("foreign").unwrap(),
                2 => {
                    key.schema.id = Id::new("source-owned.packet-native-continuation/17").unwrap();
                    binding.implementation.formats[0] = key.schema.clone();
                }
                3 => {
                    key.schema.version = 17;
                    binding.implementation.formats[0] = key.schema.clone();
                }
                4 => {
                    key.schema.definition =
                        canonical::content_ref(b"substituted", "application/json").unwrap()
                }
                5 => binding.implementation.formats.clear(),
                6 => binding.operating_contract.facets[0].version = 14,
                7 => binding.operating_contract.facets.clear(),
                _ => binding.implementation.implementation_id = Id::new("foreign").unwrap(),
            }

            assert!(!matches_selected_complete_state_profile(&key, &binding));
        }
    }

    #[test]
    fn family_correspondence_does_not_replace_compiled_definition_validation() {
        let (mut key, mut binding) = invocation15();
        key.schema.definition =
            canonical::content_ref(b"substituted definition", "application/json").unwrap();
        binding.implementation.formats[0] = key.schema.clone();

        assert!(matches_selected_complete_state_profile(&key, &binding));
        assert!(crucible_node_transport::reference_packet::service::native_snapshot::authenticate_native_owned14_snapshot_schema_data(&key.schema).is_err());
    }
}
