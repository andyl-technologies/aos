//! Defines one native Hello roster for import18 birth and prospective identity work.
//!
//! The declaration is bounded DATA derived from the actual selected launch. Its
//! private fixed arrays are also used by the native birth constructor; provider
//! feature inventory alone never becomes the native supported roster. Old phase
//! declarations retained by the baseline launch do not bypass the distinct
//! initial-only dispatcher or grant restoration effects.

use super::*;

#[path = "hello/materialization.rs"]
mod materialization;
#[path = "hello/registration.rs"]
mod registration;

use crate::handshake::{ConnectionAuthority, EXTENSION_NEGOTIATION_V1};
use crate::reference_packet::service::{
    PacketNative5LaunchValidationFields, PacketNative5SourceLaunch, ack_emitter,
    capture_allocation, confirmation, fresh_restore_allocation,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{IdSet, MAX_ID_BYTES};
pub(in crate::reference_packet) use materialization::{
    native_import18_hello_negotiated_projection_data,
    native_import18_hello_normalization_projection_data,
    native_import18_hello_projection_counter_scratch_data,
    native_import18_hello_registration_projection_data,
};
pub use registration::{
    PacketNativeImport18ProspectiveHostRegistrationData, PacketNativeImport18RegistrationSideData,
    authenticate_native_import18_current_host_registration_data,
    native_import18_current_registration_wire_data,
    native_import18_prospective_host_registration_data,
    native_import18_prospective_host_registration_from_fields_data,
    native_import18_registration_counter_scratch_data,
};
use std::collections::BTreeMap;
use std::mem::{align_of, size_of};

use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::hello as shared;

use shared::{FEATURES, KEYS};
pub use shared::{NATIVE_IMPORT18_CONNECTION_ID, PacketNativeImport18HelloSelectionData};

/// Retains the original upper declaration boundary for live authority checks.
///
/// The sole roster definition belongs to shared immutable DATA. This wrapper
/// grants no mutable access, authority conversion or native permission.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PacketNativeImport18HelloDeclarationData {
    data: shared::PacketNativeImport18HelloDeclarationData,
}

impl std::ops::Deref for PacketNativeImport18HelloDeclarationData {
    type Target = shared::PacketNativeImport18HelloDeclarationData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Derives the original declaration from the same complete launch selectors.
///
/// # Errors
/// Preserves the original required tuple, sole binding and fixed-roster errors.
pub fn native_import18_hello_declaration_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    shared::native_import18_hello_declaration_data(launch)
        .map(|data| PacketNativeImport18HelloDeclarationData { data })
}

/// Derives the original declaration from immutable borrowed launch fields.
///
/// # Errors
/// Preserves the original tuple, sole binding and fixed-roster errors.
pub fn native_import18_hello_declaration_from_fields_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    shared::native_import18_hello_declaration_from_fields_data(fields)
        .map(|data| PacketNativeImport18HelloDeclarationData { data })
}

pub(crate) fn declaration_for_selections_data(
    restoration: Option<super::super::PacketNative5CompleteRestoreSelection>,
    capture_allocation: bool,
    fresh_allocation: bool,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    shared::declaration_for_selections_data(restoration, capture_allocation, fresh_allocation)
        .map(|data| PacketNativeImport18HelloDeclarationData { data })
}

impl PacketNativeImport18HelloDeclarationData {
    // Wrapper construction, lower return, map receiver/return and borrowed views
    // are new actual controls; upper authority loans remain owned by this layer.
    fn wrapper_counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<shared::PacketNativeImport18HelloDeclarationData>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<shared::PacketNativeImport18HelloDeclarationData, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&shared::PacketNativeImport18HelloDeclarationData>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
    }

    /// Names the original upper declaration and its new immutable adapter controls.
    pub(crate) fn declaration_counter_scratch_data() -> usize {
        shared::PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
            + size_of::<&ConnectionAuthority>()
            + Self::wrapper_counter_scratch_data()
    }

    /// Quotes the same direct registration-name construction through the DATA owner.
    ///
    /// # Errors
    /// Preserves the defining backing errors and refuses adapter-counter overflow.
    pub fn registration_names_construction_storage_data(
        &self,
    ) -> Result<[usize; 3], ProviderError> {
        let mut row = self.data.registration_names_construction_storage_data()?;
        row[2] = row[2]
            .checked_add(Self::wrapper_counter_scratch_data())
            .and_then(|n| n.checked_add(size_of::<&ConnectionAuthority>()))
            .ok_or_else(refused)?;
        Ok(row)
    }

    /// Names actual direct name construction and upper adapter controls.
    pub fn registration_names_counter_scratch_data() -> usize {
        shared::PacketNativeImport18HelloDeclarationData::registration_names_counter_scratch_data()
            + size_of::<&ConnectionAuthority>()
            + Self::wrapper_counter_scratch_data()
    }

    /// Quotes the same native feature and envelope-key construction.
    ///
    /// # Errors
    /// Preserves the defining backing errors and refuses adapter-counter overflow.
    pub fn selection_construction_storage_data(&self) -> Result<[usize; 3], ProviderError> {
        let mut row = self.data.selection_construction_storage_data()?;
        row[2] = row[2]
            .checked_add(Self::wrapper_counter_scratch_data())
            .and_then(|n| n.checked_add(size_of::<&ConnectionAuthority>()))
            .ok_or_else(refused)?;
        Ok(row)
    }
    /// Checks the actual negotiated roster without constructing another authority.
    ///
    /// # Errors
    /// Refuses a revoked authority or any missing, extra or duplicate feature/key.
    pub fn authenticate_authority_data(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        if authority.selected_features().len() != self.data.feature_count_data()
            || authority.envelope_extensions().len() != self.data.key_count_data()
        {
            return Err(refused());
        }
        for name in self.data.features_data().iter().flatten() {
            let mut matches = 0usize;
            for id in authority.selected_features() {
                if id.as_str() == *name {
                    matches = matches.checked_add(1).ok_or_else(refused)?;
                }
            }
            if matches != 1 {
                return Err(refused());
            }
        }
        for (key, _) in self.data.keys_data().iter().flatten() {
            if !authority.envelope_extensions().contains(*key) {
                return Err(refused());
            }
        }
        authority.ensure_live()
    }

    /// Quotes the future authority clone and one maximum-width request Id clone.
    ///
    /// Session and incarnation come from the actual sole target binding. The
    /// connection name is the defining native birth literal; the request Id uses
    /// the defining Id grammar bound, checked again against the actual identity
    /// construction before its phase clone. Existing Arc roots allocate no clone
    /// payload. This row excludes original authority/Hello construction, tree-map
    /// negotiation work, parser/factory work and the enclosing identity header.
    ///
    /// # Errors
    /// Refuses overflow or a changed sole target binding/declaration.
    pub fn prospective_identity_storage_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<[usize; 3], ProviderError> {
        let actual = native_import18_hello_declaration_data(launch)?;
        if self.data.features_data() != actual.data.features_data()
            || self.data.keys_data() != actual.data.keys_data()
        {
            return Err(refused());
        }
        let binding = launch
            .selection
            .realization
            .bindings
            .first()
            .ok_or_else(refused)?;
        let mut retained = NATIVE_IMPORT18_CONNECTION_ID
            .len()
            .checked_add(binding.authority.session_id.as_str().len())
            .and_then(|value| value.checked_add(binding.authority.incarnation_id.as_str().len()))
            .and_then(|value| value.checked_add(MAX_ID_BYTES))
            .and_then(|value| {
                value.checked_add(
                    self.data
                        .feature_count_data()
                        .checked_mul(size_of::<Id>())?,
                )
            })
            .ok_or_else(refused)?;
        for name in self.data.features_data().iter().flatten() {
            retained = retained.checked_add(name.len()).ok_or_else(refused)?;
        }
        for (key, _) in self.data.keys_data().iter().flatten() {
            retained = retained.checked_add(key.len()).ok_or_else(refused)?;
        }
        retained = retained
            .checked_add(tree_storage_data(
                1,
                self.data.key_count_data(),
                size_of::<String>(),
                align_of::<String>(),
            )?)
            .ok_or_else(refused)?;
        let transient = size_of::<crate::connection::NativeImport18ConnectionIdentity>()
            + size_of::<Option<crate::connection::NativeImport18ConnectionIdentity>>()
            + size_of::<ConnectionAuthority>()
            + size_of::<Option<ConnectionAuthority>>()
            + size_of::<Id>()
            + size_of::<Option<Id>>();
        Ok([retained, transient, Self::counter_scratch_data()])
    }

    /// Names the exact fixed declaration, borrowed roster and clone-quote controls.
    pub fn counter_scratch_data() -> usize {
        Self::declaration_counter_scratch_data()
            + crate::connection::NativeImport18ConnectionIdentity::counter_scratch_data()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native import18 Hello declaration changed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_registration_names_match_same_closed_selection_without_a_map_copy() {
        for selection in [
            None,
            Some(super::super::super::PacketNative5CompleteRestoreSelection::SourceSignedOwned11),
            Some(
                super::super::super::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
            ),
        ] {
            let declaration = declaration_for_selections_data(selection, true, true).unwrap();
            let mut selected = None;
            declaration
                .retain_selection_into_data(&mut selected)
                .unwrap();
            let (features, keys) = selected.as_ref().unwrap();
            let mut output = None;
            declaration
                .retain_registration_names_into_data(&mut output)
                .unwrap();
            let (actual_features, actual_keys) = output.as_ref().unwrap();
            assert_eq!(features, actual_features);
            assert!(keys.keys().eq(actual_keys.iter()));
            let actual_retained = actual_features.capacity() * size_of::<Id>()
                + actual_features
                    .iter()
                    .map(Id::allocated_capacity)
                    .sum::<usize>()
                + actual_keys.capacity() * size_of::<String>()
                + actual_keys.iter().map(String::capacity).sum::<usize>();
            assert_eq!(
                declaration
                    .registration_names_construction_storage_data()
                    .unwrap()[0],
                actual_retained
            );
            let features_address = actual_features.as_ptr();
            let envelope_address = actual_keys.as_ptr();
            assert!(
                declaration
                    .retain_registration_names_into_data(&mut output)
                    .is_err()
            );
            let (actual_features, actual_keys) = output.as_ref().unwrap();
            assert_eq!(features_address, actual_features.as_ptr());
            assert_eq!(envelope_address, actual_keys.as_ptr());
        }
    }

    #[test]
    fn complete_closed_roster_fits_its_exact_declared_arrays() {
        let actual = declaration_for_selections_data(
            Some(
                super::super::super::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
            ),
            true,
            true,
        )
        .unwrap();
        assert_eq!(actual.data.feature_count_data(), FEATURES);
        assert_eq!(actual.data.key_count_data(), KEYS);
        let mut retained = None;
        actual.retain_selection_into_data(&mut retained).unwrap();
        let (features, keys) = retained.as_ref().unwrap();
        assert_eq!(features.len(), FEATURES);
        assert_eq!(keys.len(), KEYS);
        assert!(features.windows(2).all(|pair| pair[0] < pair[1]));
        for phase in [
            PacketNativeImport18Phase::Prepare,
            PacketNativeImport18Phase::Commit,
        ] {
            assert_eq!(
                keys.get(phase.proof_extension()).unwrap().as_str(),
                NATIVE_IMPORT18_EXTENSION
            );
        }
        assert_eq!(
            keys.get(super::super::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
                .unwrap()
                .as_str(),
            bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE
        );
    }

    #[test]
    fn exact_restore_selection_and_profile_toggles_keep_unique_feature_owners() {
        use crate::reference_packet::service::complete_restore::{self, transfer::*};
        use complete_restore::PacketNative5CompleteRestoreSelection::{
            SourceSignedOwned11, SourceSignedTransfer12,
        };

        for (selection, base_features, base_keys) in [
            (None, 12, 20),
            (Some(SourceSignedOwned11), 15, 23),
            (Some(SourceSignedTransfer12), 23, 27),
        ] {
            for capture in [false, true] {
                for fresh in [false, true] {
                    let declaration =
                        declaration_for_selections_data(selection, capture, fresh).unwrap();
                    let mut retained = None;
                    declaration
                        .retain_selection_into_data(&mut retained)
                        .unwrap();
                    let (features, keys) = retained.as_ref().unwrap();
                    let expected_features =
                        base_features + usize::from(capture) + usize::from(fresh);
                    let expected_keys = base_keys + 2 * usize::from(fresh);
                    assert_eq!(declaration.data.feature_count_data(), expected_features);
                    assert_eq!(declaration.data.key_count_data(), expected_keys);
                    assert_eq!(features.len(), expected_features);
                    assert_eq!(keys.len(), expected_keys);
                    assert!(features.windows(2).all(|pair| pair[0] < pair[1]));

                    // These are the defining legacy production roster helpers,
                    // independent of the new import18 constructor under test.
                    if let Some(selection) = selection {
                        for feature in
                            complete_restore::complete_restore_selected_features(selection)
                        {
                            assert_eq!(
                                features.iter().filter(|id| id.as_str() == feature).count(),
                                1
                            );
                        }
                        for key in complete_restore::complete_restore_selected_envelope_extensions(
                            selection,
                        ) {
                            assert_eq!(keys.get(key).unwrap().as_str(), key);
                        }
                    }
                    for phase in [
                        PacketNativeImport18Phase::Prepare,
                        PacketNativeImport18Phase::Commit,
                    ] {
                        let request = phase.request_extension();
                        let owner = if selection == Some(SourceSignedTransfer12) {
                            request
                        } else {
                            NATIVE_IMPORT18_EXTENSION
                        };
                        assert_eq!(keys.get(request).unwrap().as_str(), owner);
                        assert_eq!(
                            features.iter().any(|id| id.as_str() == request),
                            selection == Some(SourceSignedTransfer12)
                        );
                        assert_eq!(
                            keys.get(phase.proof_extension()).unwrap().as_str(),
                            NATIVE_IMPORT18_EXTENSION
                        );
                        assert_eq!(
                            keys.get(phase.receipt_extension()).unwrap().as_str(),
                            NATIVE_IMPORT18_EXTENSION
                        );
                    }
                    assert_eq!(
                        keys.get(NATIVE_IMPORT18_EXTENSION).unwrap().as_str(),
                        NATIVE_IMPORT18_EXTENSION
                    );
                    assert_eq!(
                        features
                            .iter()
                            .any(|id| id.as_str() == PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE),
                        selection == Some(SourceSignedTransfer12)
                    );
                    assert_eq!(
                        features.iter().any(|id| id.as_str()
                            == capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE),
                        capture
                    );
                    assert_eq!(
                        features.iter().any(|id| id.as_str()
                            == fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_FEATURE),
                        fresh
                    );
                    for key in [
                        fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
                        fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
                    ] {
                        assert_eq!(keys.contains_key(key), fresh);
                    }
                }
            }
        }
        assert_eq!(FEATURES, 25);
        assert_eq!(KEYS, 29);
    }
}
