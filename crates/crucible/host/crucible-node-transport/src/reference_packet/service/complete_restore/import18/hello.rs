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
mod registration;

use crate::handshake::{ConnectionAuthority, EXTENSION_NEGOTIATION_V1};
use crate::reference_packet::service::{
    PacketNative5SourceLaunch, ack_emitter, capture_allocation, confirmation,
    fresh_restore_allocation,
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
    native_import18_registration_counter_scratch_data,
};
use std::collections::BTreeMap;
use std::mem::{align_of, size_of};

// Base4, confirmation1, ACK2, restore3, transfer2 plus its six phase keys,
// negotiation1, capture1,
// fresh-query1 and the three independently versioned import18 definitions plus the bootstrap method feature.
const FEATURES: usize = 4 + 1 + 2 + 3 + 2 + 6 + 1 + 1 + 1 + 4;
// Input1, confirmation1, ACK1, restore3, transfer6, negotiation1, fresh-query2,
// import18 binding/proof/receipt5, stage17 grammar7 and bootstrapACK18 keys2.
// Selected transfer12 already owns the two reused request12 keys. Without that
// selection those two keys join import18 instead; the smaller roster still fits.
const KEYS: usize = 1 + 1 + 1 + 3 + 6 + 1 + 2 + 5 + 7 + 2;

/// Names the actual native connection ID used by this birth constructor.
pub const NATIVE_IMPORT18_CONNECTION_ID: &str = "packet-native5-original-connection";

/// Retains the exact prospective feature and envelope-key names without allocation.
///
/// This DATA grants neither a negotiation nor an initial allowance. The actual
/// Source/Birth owner independently authenticates its launch, full definitions,
/// private bootstrap and original funding before constructing native owners.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PacketNativeImport18HelloDeclarationData {
    features: [Option<&'static str>; FEATURES],
    feature_count: usize,
    keys: [Option<(&'static str, &'static str)>; KEYS],
    key_count: usize,
}

/// Holds a retained partial native Hello selection before fallible construction.
pub type PacketNativeImport18HelloSelectionData = (IdSet, BTreeMap<String, Id>);

/// Derives the native declaration from the actual complete launch selectors.
///
/// Full launch and three-definition validation are independently funded by the
/// caller. This allocation-free constructor neither calls those factories nor
/// infers the requested import mechanism from feature or schema membership.
///
/// # Errors
/// Refuses an absent required ACK/confirmation/metadata tuple, an empty or
/// ambiguous target binding, or an inconsistent defining fixed roster.
pub fn native_import18_hello_declaration_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    if launch.schema_version != 5
        || launch.ack_emitter_selection.is_none()
        || launch.confirmation_selection.is_none()
        || launch.protocol_metadata_limits.is_none()
        || launch.selection.realization.bindings.len() != 1
    {
        return Err(refused());
    }
    declaration_for_selections_data(
        launch.complete_restore_selection,
        launch.capture_allocation_selection.is_some(),
        launch.fresh_restore_allocation_selection.is_some(),
    )
}

// Native5Policy consumes these same actual immutable selectors. This pure DATA
// constructor grants no Source purpose and performs no installed-schema work.
pub(crate) fn declaration_for_selections_data(
    restoration: Option<super::super::PacketNative5CompleteRestoreSelection>,
    capture_allocation: bool,
    fresh_allocation: bool,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    let mut declaration = PacketNativeImport18HelloDeclarationData {
        features: [None; FEATURES],
        feature_count: 0,
        keys: [None; KEYS],
        key_count: 0,
    };
    for feature in [
        "cnp.control-evidence/1",
        "cnp.core/1",
        crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_FEATURE,
        crate::reference_packet::input::PACKET_INPUT_FEATURE,
    ] {
        declaration.feature(feature)?;
    }
    let input = crate::reference_packet::input::PACKET_INPUT_FEATURE;
    declaration.key(input, input)?;

    let confirmation = confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE;
    declaration.feature(confirmation)?;
    declaration.key(
        confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION,
        confirmation,
    )?;
    declaration.feature(ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE)?;
    let admission = ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE;
    declaration.feature(admission)?;
    declaration.key(admission, admission)?;

    if restoration.is_some() {
        for key in [
            super::super::PACKET_COMPLETE_RESTORE_FEATURE,
            super::super::PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
            super::super::PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        ] {
            declaration.feature(key)?;
            declaration.key(key, key)?;
        }
    }
    if restoration
        == Some(super::super::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
    {
        use super::super::transfer::*;
        declaration.feature(PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE)?;
        declaration.feature(super::super::PACKET_NATIVE_RESTORED_RECORD_FEATURE)?;
        for phase in [
            PacketCompleteRestoreTransferPhase::Prepare,
            PacketCompleteRestoreTransferPhase::Commit,
        ] {
            for key in [
                phase.request_extension(),
                phase.proof_extension(),
                phase.receipt_extension(),
            ] {
                // The old native birth declares these exact keys as features.
                declaration.feature(key)?;
                declaration.key(key, key)?;
            }
        }
    }
    declaration.feature(EXTENSION_NEGOTIATION_V1)?;
    declaration.key(EXTENSION_NEGOTIATION_V1, EXTENSION_NEGOTIATION_V1)?;
    if capture_allocation {
        declaration.feature(capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)?;
    }
    if fresh_allocation {
        let feature = fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_FEATURE;
        declaration.feature(feature)?;
        for key in [
            fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
        ] {
            declaration.key(key, feature)?;
        }
    }

    declaration.feature(bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE)?;
    declaration.feature(NATIVE_IMPORT18_EXTENSION)?;
    declaration.feature(NATIVE_IMPORT18_STAGE_SELECTION)?;
    declaration.feature(NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA)?;
    declaration.key(NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_EXTENSION)?;
    for phase in [
        PacketNativeImport18Phase::Prepare,
        PacketNativeImport18Phase::Commit,
    ] {
        if restoration
            == Some(super::super::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            declaration.reuse_transfer_request_key(phase)?;
        } else {
            declaration.key(phase.request_extension(), NATIVE_IMPORT18_EXTENSION)?;
        }
        for key in [phase.proof_extension(), phase.receipt_extension()] {
            declaration.key(key, NATIVE_IMPORT18_EXTENSION)?;
        }
    }
    use super::super::import17::stage::{
        NATIVE_IMPORT17_STAGE_EXTENSION, PacketNativeImport17Stage,
    };
    declaration.key(
        NATIVE_IMPORT17_STAGE_EXTENSION,
        NATIVE_IMPORT18_STAGE_SELECTION,
    )?;
    for phase in [
        PacketNativeImport17Stage::Arm,
        PacketNativeImport17Stage::World,
        PacketNativeImport17Stage::FirstObserve,
    ] {
        declaration.key(phase.proof_extension(), NATIVE_IMPORT18_STAGE_SELECTION)?;
        declaration.key(phase.receipt_extension(), NATIVE_IMPORT18_STAGE_SELECTION)?;
    }
    for key in [
        super::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        super::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
    ] {
        declaration.key(key, bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE)?;
    }
    Ok(declaration)
}

impl PacketNativeImport18HelloDeclarationData {
    /// Quotes direct registration-name vectors from this exact native roster.
    ///
    /// This distinct planned output needs no negotiation map or map clone. It
    /// grants no registration, Initial, Source purpose or native permission.
    ///
    /// # Errors
    /// Refuses checked backing arithmetic overflow.
    pub fn registration_names_construction_storage_data(
        &self,
    ) -> Result<[usize; 3], ProviderError> {
        let mut retained = self
            .feature_count
            .checked_mul(size_of::<Id>())
            .and_then(|bytes| bytes.checked_add(self.key_count.checked_mul(size_of::<String>())?))
            .ok_or_else(refused)?;
        for name in self.features.iter().flatten() {
            retained = retained.checked_add(name.len()).ok_or_else(refused)?;
        }
        for (key, _) in self.keys.iter().flatten() {
            retained = retained.checked_add(key.len()).ok_or_else(refused)?;
        }
        // uninit's owned return and ptr::swap's owned tmp are distinct roles.
        // Id swaps and String swaps execute in separate completed loops.
        let swap_transient = (size_of::<std::mem::MaybeUninit<Id>>() * 2)
            .max(size_of::<std::mem::MaybeUninit<String>>() * 2);
        let transient = size_of::<IdSet>()
            + size_of::<Vec<String>>()
            + size_of::<(IdSet, Vec<String>)>()
            + size_of::<Option<(IdSet, Vec<String>)>>()
            // Constructor return, push input, push_mut input and write input.
            + size_of::<String>() * 4
            + size_of::<Vec<u8>>()
            + size_of::<Id>() * 4
            + swap_transient
            + size_of::<Result<Id, crucible_node_format::ContractError>>()
            + size_of::<Result<Id, (String, crucible_node_format::ContractError)>>()
            + size_of::<Result<(), std::collections::TryReserveError>>();
        Ok([
            retained,
            transient,
            Self::registration_names_counter_scratch_data(),
        ])
    }

    /// Builds sorted feature and envelope-name vectors in one retained output.
    ///
    /// Every allocated child stays under the caller's same output. The caller
    /// admits the complete defining row before invoking this constructor.
    ///
    /// # Errors
    /// Refuses occupied output, allocation failure or invalid fixed identifiers.
    /// Successful partial children remain installed on refusal or unwind.
    pub fn retain_registration_names_into_data(
        &self,
        output: &mut Option<(IdSet, Vec<String>)>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some((Vec::new(), Vec::new()));
        let (features, envelope) = output.as_mut().ok_or_else(refused)?;
        features
            .try_reserve_exact(self.feature_count)
            .map_err(|_| refused())?;
        envelope
            .try_reserve_exact(self.key_count)
            .map_err(|_| refused())?;
        for name in self.features.iter().flatten() {
            features.push(Id::new(*name)?);
        }
        for (key, _) in self.keys.iter().flatten() {
            envelope.push(String::from(*key));
        }
        // Both fixed rosters are unique. In-place insertion preserves every
        // same allocated child and needs no library sorter or temporary bank.
        for index in 1..features.len() {
            let mut destination = index;
            while destination != 0 && features[destination] < features[destination - 1] {
                features.swap(destination, destination - 1);
                destination -= 1;
            }
        }
        for index in 1..envelope.len() {
            let mut destination = index;
            while destination != 0 && envelope[destination] < envelope[destination - 1] {
                envelope.swap(destination, destination - 1);
                destination -= 1;
            }
        }
        Ok(())
    }

    /// Names direct vector construction and its actual declaration controls.
    pub fn registration_names_counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&mut Option<(IdSet, Vec<String>)>>()
            + size_of::<Option<&mut (IdSet, Vec<String>)>>()
            + size_of::<Result<&mut (IdSet, Vec<String>), ProviderError>>()
            + size_of::<(&mut IdSet, &mut Vec<String>)>()
            + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
            + size_of::<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
            + size_of::<
                std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
            >()
            + size_of::<Option<&&'static str>>()
            + size_of::<Option<&(&'static str, &'static str)>>()
            + size_of::<&Id>() * 2
            + size_of::<&String>() * 2
            + size_of::<&mut [Id]>()
            + size_of::<&mut [String]>()
            + size_of::<std::cmp::Ordering>()
            + size_of::<&str>() * 2
            + size_of::<&[u8]>() * 2
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<Option<u8>>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<usize>() * 6
            + size_of::<Option<usize>>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + Self::registration_names_push_counter_scratch_data::<Id>()
                .max(Self::registration_names_push_counter_scratch_data::<String>())
            + Self::registration_names_swap_counter_scratch_data::<Id>()
                .max(Self::registration_names_swap_counter_scratch_data::<String>())
            + Self::declaration_counter_scratch_data()
    }

    fn registration_names_push_counter_scratch_data<T>() -> usize {
        // Builder loan, push, push_mut and as_mut_ptr receiver; push_mut's
        // returned element loan and the wrapper's discarded returned loan.
        size_of::<&mut Vec<T>>() * 4
            + size_of::<&mut T>() * 2
            // as_mut_ptr, add, end and ptr::write's destination argument.
            + size_of::<*mut T>() * 4
            + size_of::<usize>() * 2
    }

    fn registration_names_swap_counter_scratch_data<T>() -> usize {
        // Vec's slice loan and slice::swap's receiver, then the two index loans.
        size_of::<&mut [T]>() * 2
            + size_of::<&mut T>() * 2
            // slice pa/pb, ptr::swap x/y, tmp.as_mut_ptr and copy destinations.
            + size_of::<*mut T>() * 7
            // tmp.as_ptr, source coercion and the copy source argument.
            + size_of::<*const T>() * 3
            + size_of::<&mut std::mem::MaybeUninit<T>>()
            + size_of::<&std::mem::MaybeUninit<T>>()
            + size_of::<*mut std::mem::MaybeUninit<T>>()
            + size_of::<*const std::mem::MaybeUninit<T>>()
            + size_of::<usize>() * 3
    }

    fn feature(&mut self, name: &'static str) -> Result<(), ProviderError> {
        if self.features.iter().flatten().any(|actual| *actual == name) {
            return Err(refused());
        }
        let destination = self
            .features
            .get_mut(self.feature_count)
            .ok_or_else(refused)?;
        *destination = Some(name);
        self.feature_count = self.feature_count.checked_add(1).ok_or_else(refused)?;
        Ok(())
    }

    // Only the actual Transfer12 branch may reuse its already declared payload
    // key. Keep its original key->key feature association; no duplicate insert,
    // generic deduplication or import18 proof/receipt alias is accepted here.
    fn reuse_transfer_request_key(
        &self,
        phase: PacketNativeImport18Phase,
    ) -> Result<(), ProviderError> {
        let request = phase.request_extension();
        let mut found = false;
        for (key, feature) in self.keys.iter().flatten() {
            if *key == request {
                if found || *feature != request {
                    return Err(refused());
                }
                found = true;
            }
        }
        if !found
            || !self
                .features
                .iter()
                .flatten()
                .any(|feature| *feature == request)
        {
            return Err(refused());
        }
        Ok(())
    }

    // Names the added selector comparison and exact retained-request check.
    fn request_reuse_counter_scratch_data() -> usize {
        type Selection = super::super::PacketNative5CompleteRestoreSelection;
        size_of::<&Self>()
            + size_of::<PacketNativeImport18Phase>()
            + size_of::<Option<Selection>>() * 2
            + size_of::<&Option<Selection>>() * 2
            + size_of::<Selection>()
            + size_of::<&str>()
            + size_of::<bool>() * 4
            + size_of::<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
            + size_of::<
                std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
            >()
            + size_of::<
                &mut std::iter::Flatten<
                    std::slice::Iter<'static, Option<(&'static str, &'static str)>>,
                >,
            >()
            + size_of::<&mut std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
            + size_of::<Option<&(&'static str, &'static str)>>()
            + size_of::<&(&'static str, &'static str)>()
            + size_of::<&&str>() * 2
            + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
            + size_of::<&mut std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
            + size_of::<&mut std::slice::Iter<'static, Option<&'static str>>>()
            + size_of::<Option<&&'static str>>()
            + size_of::<&&str>()
            + size_of::<Result<(), ProviderError>>() * 2
            + size_of::<ProviderError>()
            // The new disjoint proof/receipt loop has this actual two-key
            // initializer and iterator; earlier fresh/bootstrap loops ended.
            + size_of::<[&str; 2]>()
            + size_of::<std::array::IntoIter<&'static str, 2>>()
            + size_of::<&mut std::array::IntoIter<&'static str, 2>>()
            + size_of::<Option<&str>>()
    }

    fn key(&mut self, key: &'static str, feature: &'static str) -> Result<(), ProviderError> {
        if self.keys.iter().flatten().any(|(actual, _)| *actual == key)
            || !self
                .features
                .iter()
                .flatten()
                .any(|actual| *actual == feature)
        {
            return Err(refused());
        }
        let destination = self.keys.get_mut(self.key_count).ok_or_else(refused)?;
        *destination = Some((key, feature));
        self.key_count = self.key_count.checked_add(1).ok_or_else(refused)?;
        Ok(())
    }

    /// Constructs the same exact native Hello roster into a retained destination.
    ///
    /// # Errors
    /// Refuses an occupied destination, allocation failure or malformed fixed Id.
    /// The destination and every successful child remain installed on refusal.
    pub fn retain_selection_into_data(
        &self,
        output: &mut Option<PacketNativeImport18HelloSelectionData>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some((Vec::new(), BTreeMap::new()));
        let (features, keys) = output.as_mut().ok_or_else(refused)?;
        features
            .try_reserve_exact(self.feature_count)
            .map_err(|_| refused())?;
        for name in self.features.iter().flatten() {
            features.push(Id::new(*name)?);
        }
        // The finite roster needs no library sort buffer or recursive sorter.
        for index in 1..features.len() {
            let mut destination = index;
            while destination != 0 && features[destination] < features[destination - 1] {
                features.swap(destination, destination - 1);
                destination -= 1;
            }
        }
        for (key, feature) in self.keys.iter().flatten() {
            keys.insert((*key).into(), Id::new(*feature)?);
        }
        Ok(())
    }

    /// Quotes the actual retained feature Vec and envelope-key policy map.
    ///
    /// The row covers this selection builder only. The enclosing Handshake,
    /// Hello result, authority constructor and their independent clones remain
    /// distinct live owners under the initial constructor's complete row.
    ///
    /// # Errors
    /// Refuses checked backing or defining tree-node layout overflow.
    pub fn selection_construction_storage_data(&self) -> Result<[usize; 3], ProviderError> {
        let mut retained = self
            .feature_count
            .checked_mul(size_of::<Id>())
            .ok_or_else(refused)?;
        for name in self.features.iter().flatten() {
            retained = retained.checked_add(name.len()).ok_or_else(refused)?;
        }
        for (key, feature) in self.keys.iter().flatten() {
            retained = retained
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(feature.len()))
                .ok_or_else(refused)?;
        }
        retained = retained
            .checked_add(tree_storage_data(
                1,
                self.key_count,
                size_of::<(String, Id)>(),
                align_of::<(String, Id)>(),
            )?)
            .ok_or_else(refused)?;
        let transient = size_of::<PacketNativeImport18HelloSelectionData>()
            + size_of::<Option<PacketNativeImport18HelloSelectionData>>()
            + size_of::<String>()
            + size_of::<Id>()
            + size_of::<Result<Id, crucible_node_format::ContractError>>();
        Ok([
            retained,
            transient,
            Self::declaration_counter_scratch_data(),
        ])
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
        if authority.selected_features().len() != self.feature_count
            || authority.envelope_extensions().len() != self.key_count
        {
            return Err(refused());
        }
        for name in self.features.iter().flatten() {
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
        for (key, _) in self.keys.iter().flatten() {
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
        if self.features != actual.features || self.keys != actual.keys {
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
            .and_then(|value| value.checked_add(self.feature_count.checked_mul(size_of::<Id>())?))
            .ok_or_else(refused)?;
        for name in self.features.iter().flatten() {
            retained = retained.checked_add(name.len()).ok_or_else(refused)?;
        }
        for (key, _) in self.keys.iter().flatten() {
            retained = retained.checked_add(key.len()).ok_or_else(refused)?;
        }
        retained = retained
            .checked_add(tree_storage_data(
                1,
                self.key_count,
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

    /// Names only the closed declaration and its direct borrowed controls.
    ///
    /// This excludes the identity supplier, allowing its own current-policy
    /// counter to compose the real declaration check without recursion.
    pub(crate) fn declaration_counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&ConnectionAuthority>()
            + size_of::<&mut Option<PacketNativeImport18HelloSelectionData>>()
            + size_of::<PacketNativeImport18HelloSelectionData>()
            + size_of::<Option<PacketNativeImport18HelloSelectionData>>()
            + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
            + size_of::<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
            + size_of::<
                std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
            >()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<Option<&Option<&'static str>>>()
            + size_of::<Option<&mut Option<&'static str>>>()
            + size_of::<Option<&mut Option<(&'static str, &'static str)>>>()
            + size_of::<(&str, &str)>()
            + size_of::<&&str>()
            + size_of::<(&mut IdSet, &mut BTreeMap<String, Id>)>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<usize>() * 6
            + size_of::<Option<usize>>()
            + size_of::<std::alloc::Layout>()
            + size_of::<[&str; 4]>()
            + size_of::<std::array::IntoIter<&'static str, 4>>()
            + size_of::<[&str; 3]>()
            + size_of::<std::array::IntoIter<&'static str, 3>>()
            + size_of::<[&str; 2]>()
            + size_of::<std::array::IntoIter<&'static str, 2>>()
            + size_of::<[PacketNativeImport18Phase; 2]>()
            + size_of::<std::array::IntoIter<PacketNativeImport18Phase, 2>>()
            + size_of::<[super::super::transfer::PacketCompleteRestoreTransferPhase; 2]>()
            + size_of::<
                std::array::IntoIter<super::super::transfer::PacketCompleteRestoreTransferPhase, 2>,
            >()
            + size_of::<[super::super::import17::stage::PacketNativeImport17Stage; 3]>()
            + size_of::<
                std::array::IntoIter<super::super::import17::stage::PacketNativeImport17Stage, 3>,
            >()
            + size_of::<PacketNativeImport18Phase>()
            + size_of::<super::super::transfer::PacketCompleteRestoreTransferPhase>()
            + size_of::<super::super::import17::stage::PacketNativeImport17Stage>()
            + size_of::<&mut [Id]>()
            + size_of::<Option<&mut PacketNativeImport18HelloSelectionData>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<[usize; 6]>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<(), ProviderError>>()
            + Self::request_reuse_counter_scratch_data()
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
        assert_eq!(actual.feature_count, FEATURES);
        assert_eq!(actual.key_count, KEYS);
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
    fn occupied_selection_and_duplicate_names_preserve_the_original() {
        let mut actual = declaration_for_selections_data(None, false, false).unwrap();
        let mut output = None;
        actual.retain_selection_into_data(&mut output).unwrap();
        let first = output.as_ref().unwrap().0.as_ptr();
        assert!(actual.retain_selection_into_data(&mut output).is_err());
        assert_eq!(output.as_ref().unwrap().0.as_ptr(), first);
        let features = actual.feature_count;
        let keys = actual.key_count;
        assert!(actual.feature(NATIVE_IMPORT18_EXTENSION).is_err());
        assert!(
            actual
                .key(NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_EXTENSION)
                .is_err()
        );
        assert_eq!(actual.feature_count, features);
        assert_eq!(actual.key_count, keys);
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
                    assert_eq!(declaration.feature_count, expected_features);
                    assert_eq!(declaration.key_count, expected_keys);
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

    #[test]
    fn reused_requests_still_refuse_duplicate_insert_and_foreign_feature_owners() {
        use crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12;
        let original =
            declaration_for_selections_data(Some(SourceSignedTransfer12), true, true).unwrap();
        for phase in [
            PacketNativeImport18Phase::Prepare,
            PacketNativeImport18Phase::Commit,
        ] {
            let mut actual = original;
            let request = phase.request_extension();
            let feature_count = actual.feature_count;
            let key_count = actual.key_count;
            actual.reuse_transfer_request_key(phase).unwrap();
            assert!(actual.key(request, request).is_err());
            assert!(actual.key(request, NATIVE_IMPORT18_EXTENSION).is_err());
            assert!(actual.key(phase.proof_extension(), request).is_err());
            assert!(
                actual
                    .key(
                        "source-owned.foreign-key/18",
                        "source-owned.unselected-feature/18"
                    )
                    .is_err()
            );
            assert_eq!(actual.feature_count, feature_count);
            assert_eq!(actual.key_count, key_count);
            assert!(actual == original);
        }
    }

    #[test]
    fn retained_request_reuse_checks_one_exact_mapping_and_its_feature() {
        use crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::{SourceSignedOwned11, SourceSignedTransfer12};
        let original =
            declaration_for_selections_data(Some(SourceSignedTransfer12), true, true).unwrap();
        for phase in [
            PacketNativeImport18Phase::Prepare,
            PacketNativeImport18Phase::Commit,
        ] {
            let request = phase.request_extension();
            let position = original
                .keys
                .iter()
                .position(|row| row.as_ref().is_some_and(|(key, _)| *key == request))
                .unwrap();
            let mut foreign = original;
            foreign.keys[position] = Some((request, NATIVE_IMPORT18_EXTENSION));
            assert!(foreign.reuse_transfer_request_key(phase).is_err());
            let mut missing = original;
            missing.keys[position] = None;
            assert!(missing.reuse_transfer_request_key(phase).is_err());
            let mut duplicate = original;
            let other = original
                .keys
                .iter()
                .position(|row| {
                    row.as_ref()
                        .is_some_and(|(key, _)| *key == NATIVE_IMPORT18_EXTENSION)
                })
                .unwrap();
            duplicate.keys[other] = Some((request, request));
            assert!(duplicate.reuse_transfer_request_key(phase).is_err());
            let mut missing_feature = original;
            let feature = original
                .features
                .iter()
                .position(|entry| *entry == Some(request))
                .unwrap();
            missing_feature.features[feature] = None;
            assert!(missing_feature.reuse_transfer_request_key(phase).is_err());
            // Neither smaller selector may use the legacy-owner reuse path.
            for selection in [None, Some(SourceSignedOwned11)] {
                let actual = declaration_for_selections_data(selection, true, true).unwrap();
                assert!(actual.reuse_transfer_request_key(phase).is_err());
            }
        }
    }
}
