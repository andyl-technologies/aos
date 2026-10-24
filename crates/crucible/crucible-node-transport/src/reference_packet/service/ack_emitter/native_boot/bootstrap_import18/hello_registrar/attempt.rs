//! Retains fresh registrar configuration, issuer, empty registry and failures.
//!
//! The enclosing bootstrap must independently calculate/admit the complete row
//! and authenticate its original inputs around this constructor. This owner
//! alone supplies no Source funding, connection lease, native policy or reply.

use crate::ProviderError;
use crate::handshake::{
    ConnectionAuthority, ExtensionHandshake, Handshake, NegotiationPolicy, TrustedInstallation,
};
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18HelloSelectionData;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use crate::reference_packet::service::server::complete::birth::EmptyBootExtensions;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::ContractError;
use std::mem::size_of;
use std::rc::Rc;

#[path = "initial_admission.rs"]
mod initial_admission;

/// Retains every physical fresh-registrar owner before an initial exchange.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    row: Option<[usize; 3]>,
    cut: Option<OperationalDeadline>,
    installation: Option<TrustedInstallation>,
    policy: Option<NegotiationPolicy>,
    handshake: Option<Handshake>,
    registry: Option<Rc<EmptyBootExtensions>>,
    wrapper: Option<ExtensionHandshake>,
    failure: Option<ProviderError>,
    admission_started: bool,
    authority: Option<ConnectionAuthority>,
    admission_failure: Option<ProviderError>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Configured,
    Issuer,
    Registry,
    Wrapped,
    Complete,
    Failed,
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        stage: _,
        row: _,
        cut: _,
        installation: _,
        policy: _,
        handshake: _,
        registry: _,
        wrapper: _,
        failure: _,
        admission_started: _,
        authority: _,
        admission_failure: _,
    } = value;
};

impl Attempt {
    /// Initializes empty physical slots without allocating a configuration.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            row: None,
            cut: None,
            installation: None,
            policy: None,
            handshake: None,
            registry: None,
            wrapper: None,
            failure: None,
            admission_started: false,
            authority: None,
            admission_failure: None,
        }
    }

    /// Spends this occurrence before any enclosing input or admission guard.
    ///
    /// # Errors
    /// Refuses a foreign creator or a previously spent attempt.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the actual independent constructor row before allocation.
    ///
    /// # Errors
    /// Refuses foreign custody, an occupied row or an incorrect stage.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Constructs retained configuration and a fresh unselected registry wrapper.
    ///
    /// The original cut is never renewed. Configuration slots survive actual
    /// validation errors; successful issuer/wrapper moves preserve their real
    /// allocations. No verifier callback, connection admission or I/O runs here.
    ///
    /// # Errors
    /// Refuses stale custody, foreign/incomplete original fields, occupied
    /// slots, actual configuration validation or wrapper construction failure.
    pub(super) fn construct_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        selection: &PacketNativeImport18HelloSelectionData,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        let outcome = self.construct_current_data(launch, selection, cut);
        let terminal = self.guard(cut);
        if let Err(error) = outcome.and(terminal) {
            self.stage = Stage::Failed;
            return Err(error);
        }
        Ok(())
    }

    fn construct_current_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        selection: &PacketNativeImport18HelloSelectionData,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.installation.is_some()
            || self.policy.is_some()
            || self.handshake.is_some()
            || self.registry.is_some()
            || self.wrapper.is_some()
            || self.failure.is_some()
            || self.admission_started
            || self.authority.is_some()
            || self.admission_failure.is_some()
            || launch.selection.realization.bindings.len() != 1
        {
            return Err(refused());
        }
        authenticate_selection_data(launch, selection)?;
        self.guard(cut)?;
        let token: [u8; 32] = launch
            .admission_token
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let binding = launch
            .selection
            .realization
            .bindings
            .first()
            .ok_or_else(refused)?;
        self.installation = Some(TrustedInstallation {
            session_id: binding.authority.session_id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            measured_implementation: launch.selection.provider.implementation.clone(),
            launch_receipt: launch.selection.admission_receipt.clone(),
            admission_token: token,
        });
        self.policy = Some(NegotiationPolicy {
            supported_features: selection.0.clone(),
            required_features: selection.0.clone(),
            provider_limits: launch.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref.clone(),
            envelope_extension_features: selection.1.clone(),
        });
        self.stage = Stage::Configured;
        self.guard(cut)?;

        if let Err(error) = Handshake::from_retained_configuration_data(
            &mut self.installation,
            &mut self.policy,
            &mut self.handshake,
        ) {
            self.failure = Some(error);
            self.stage = Stage::Failed;
            return Err(refused());
        }
        self.stage = Stage::Issuer;
        self.guard(cut)?;
        self.registry = Some(Rc::new(EmptyBootExtensions));
        self.stage = Stage::Registry;
        let registry = self.registry.as_ref().ok_or_else(refused)?;
        match ExtensionHandshake::from_original_empty_retained(&mut self.handshake, registry) {
            Ok(wrapper) => self.wrapper = Some(wrapper),
            Err(error) => {
                self.failure = Some(error);
                self.stage = Stage::Failed;
                return Err(refused());
            }
        }
        self.stage = Stage::Wrapped;
        self.guard(cut)
    }

    /// Completes only after the enclosing original terminal checks and census.
    ///
    /// # Errors
    /// Refuses foreign custody or incomplete/refused physical construction.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.guard(self.cut.ok_or_else(refused)?)?;
        if self.stage != Stage::Wrapped
            || self.wrapper.is_none()
            || self.failure.is_some()
            || self.admission_started
            || self.authority.is_some()
            || self.admission_failure.is_some()
        {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Closes the attempt while preserving its actual initialized owners.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Borrows the actual completed wrapper under the same retained cut.
    ///
    /// # Errors
    /// Refuses stale custody, a substituted/expired cut or incomplete/refused construction.
    pub(super) fn data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<&ExtensionHandshake, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete
            || self.failure.is_some()
            || self.admission_started
            || self.authority.is_some()
            || self.admission_failure.is_some()
        {
            return Err(refused());
        }
        self.wrapper.as_ref().ok_or_else(refused)
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn wrapper_fixture_data(&self) -> Option<&ExtensionHandshake> {
        self.wrapper.as_ref()
    }

    #[cfg(test)]
    pub(in super::super) fn failure_fixture_data(&self) -> Option<&ProviderError> {
        self.failure.as_ref()
    }

    /// Counts all retained configuration, issuer, registry and failure backing.
    ///
    /// The erased and concrete registry edges are discounted only after the
    /// owning wrapper authenticates their actual allocation identity. Unsupported
    /// future diagnostic owners stay retained while their census fails closed.
    ///
    /// # Errors
    /// Refuses foreign custody, unknown diagnostics, changed registry ownership
    /// or checked observer/backing overflow. An expired cut does not erase data.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(installation) = &self.installation {
            let TrustedInstallation {
                session_id,
                incarnation_id,
                measured_implementation,
                launch_receipt,
                admission_token: _,
            } = installation;
            observer.observe(session_id)?;
            observer.observe(incarnation_id)?;
            observer.observe(measured_implementation)?;
            observer.observe(launch_receipt)?;
        }
        if let Some(policy) = &self.policy {
            let NegotiationPolicy {
                supported_features,
                required_features,
                provider_limits,
                required_schemas,
                required_guarantees,
                envelope_extension_features,
            } = policy;
            observer.observe(supported_features)?;
            observer.observe(required_features)?;
            observer.observe(provider_limits)?;
            observer.observe(required_schemas)?;
            observer.observe(required_guarantees)?;
            observer.observe(envelope_extension_features)?;
        }
        let mut bytes = requested_metadata_backing_storage_data(&observer.finish())?;
        if let Some(handshake) = &self.handshake {
            bytes = add(
                bytes,
                requested_metadata_backing_storage_data(
                    &handshake.retained_metadata_facts_data()?,
                )?,
            )?;
        }
        if let Some(wrapper) = &self.wrapper {
            let registry = self.registry.as_ref().ok_or_else(refused)?;
            bytes = add(
                bytes,
                requested_metadata_backing_storage_data(
                    &wrapper.original_empty_state_metadata_facts_data(
                        registry,
                        self.authority.as_ref(),
                    )?,
                )?,
            )?;
        } else if self.authority.is_some() {
            return Err(refused());
        } else if let Some(registry) = &self.registry {
            let mut observer = MetadataObserver::new();
            observer.shared_value(registry.as_ref())?;
            bytes = add(
                bytes,
                requested_metadata_backing_storage_data(&observer.finish())?,
            )?;
        }
        for failure in [&self.failure, &self.admission_failure]
            .into_iter()
            .flatten()
        {
            match failure {
                ProviderError::Contract(ContractError::Invalid { reason, .. }) => {
                    bytes = add(bytes, reason.capacity())?
                }
                ProviderError::Contract(ContractError::Overflow)
                | ProviderError::Frame(_)
                | ProviderError::Correlation(_)
                | ProviderError::ResourceExhausted(_)
                | ProviderError::Conflict(_) => {}
                ProviderError::Io(error) if error.get_ref().is_none() => {
                    // Rust 1.98.1 core/src/io/error.rs returns None exactly for
                    // Os, Simple and static SimpleMessage. Their storage stays
                    // inside the already retained Error header; Custom always
                    // exposes its owned error through Some. This observation
                    // invokes no diagnostic formatting or erased callback.
                }
                ProviderError::Io(_) | ProviderError::Contract(ContractError::Json(_)) => {
                    return Err(refused());
                }
            }
        }
        Ok(bytes)
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    /// Names actual constructor, guards, slot moves and retained census controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&PacketNativeImport18HelloSelectionData>()
            + size_of::<ProtocolCaptureOwner>()
            + size_of::<Stage>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<[u8; 32]>()
            + size_of::<Result<[u8; 32], std::array::TryFromSliceError>>()
            + size_of::<Option<&TrustedInstallation>>()
            + size_of::<Option<&NegotiationPolicy>>()
            + size_of::<Option<&Handshake>>()
            + size_of::<Option<&Rc<EmptyBootExtensions>>>()
            + size_of::<Option<&ExtensionHandshake>>()
            + size_of::<Option<&ProviderError>>()
            + size_of::<&std::io::Error>() * 3
            + size_of::<Option<&(dyn std::error::Error + Send + Sync)>>() * 3
            // get_ref's pinned representation query has one borrowed payload
            // or scalar plus a discriminant; this bounds that temporary record.
            + size_of::<usize>() * 2
            + size_of::<std::io::ErrorKind>()
            + size_of::<i32>()
            + size_of::<bool>() * 2
            + size_of::<Option<&ConnectionAuthority>>()
            + size_of::<[&Option<ProviderError>; 2]>()
            + size_of::<std::array::IntoIter<&Option<ProviderError>, 2>>()
            + size_of::<MetadataObserver<'static>>() * 2
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<
                Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>,
            >()
            + size_of::<Result<ExtensionHandshake, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<std::slice::Iter<'static, crucible_node_format::Id>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, crucible_node_format::Id>>(
            )
            + size_of::<usize>() * 4
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn authenticate_selection_data(
    launch: &PacketNative5SourceLaunch,
    selection: &PacketNativeImport18HelloSelectionData,
) -> Result<(), ProviderError> {
    let declaration = native_import18_hello_declaration_data(launch)?;
    if selection.0.len() != declaration.feature_count_data()
        || selection.1.len() != declaration.key_count_data()
    {
        return Err(refused());
    }

    for feature in declaration.features_data().iter().flatten() {
        if selection
            .0
            .iter()
            .filter(|id| id.as_str() == *feature)
            .count()
            != 1
        {
            return Err(refused());
        }
    }
    for (key, feature) in declaration.keys_data().iter().flatten() {
        if !selection.1.iter().any(|(actual_key, actual_feature)| {
            actual_key == key && actual_feature.as_str() == *feature
        }) {
            return Err(refused());
        }
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 fresh Hello registrar refused")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture(
        reactive: bool,
    ) -> (
        PacketNative5SourceLaunch,
        PacketNativeImport18HelloSelectionData,
    ) {
        let (launch, _, _) = super::super::tests::configuration_data(reactive);
        let declaration = native_import18_hello_declaration_data(&launch).unwrap();
        let mut selection = None;
        declaration
            .retain_selection_into_data(&mut selection)
            .unwrap();
        (launch, selection.unwrap())
    }

    fn cut() -> OperationalDeadline {
        OperationalDeadline::after(Duration::from_secs(5)).unwrap()
    }

    fn quoted(
        launch: &PacketNative5SourceLaunch,
        cut: OperationalDeadline,
    ) -> (Attempt, [usize; 3]) {
        let row = super::super::construction_data(launch, 268_435_456).unwrap();
        let mut attempt = Attempt::empty_data();
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
        attempt.start_data(cut).unwrap();
        attempt.quote_data(row).unwrap();
        (attempt, row)
    }

    #[test]
    fn actual_fresh_issuer_and_same_empty_registry_fit_both_configuration_rows() {
        for reactive in [false, true] {
            let (launch, selection) = fixture(reactive);
            let cut = cut();
            let (mut attempt, row) = quoted(&launch, cut);

            attempt.construct_data(&launch, &selection, cut).unwrap();

            assert!(attempt.stage == Stage::Wrapped);
            assert!(attempt.installation.is_none());
            assert!(attempt.policy.is_none());
            assert!(attempt.handshake.is_none());
            assert!(attempt.failure.is_none());
            let registry = attempt.registry.as_ref().unwrap();
            assert_eq!(Rc::strong_count(registry), 2);
            let facts = attempt
                .wrapper
                .as_ref()
                .unwrap()
                .original_empty_retained_metadata_facts_data(registry)
                .unwrap();
            assert_eq!(facts.shared_backing_views, 3);
            assert!(attempt.retained_backing_data().unwrap() <= row[0]);
            attempt.complete_data().unwrap();
            assert!(attempt.stage == Stage::Complete);
            assert!(attempt.start_data(cut).is_err());
            let peak = row.into_iter().sum::<usize>();
            assert!(super::super::construction_data(&launch, peak - 1).is_err());
        }
    }

    #[test]
    fn actual_validation_failure_keeps_configuration_and_error_without_a_fresh_gate() {
        let (mut launch, selection) = fixture(false);
        launch.selection.provider.implementation.schema_version = 2;
        let cut = cut();
        let (mut attempt, row) = quoted(&launch, cut);

        assert!(attempt.construct_data(&launch, &selection, cut).is_err());

        assert!(attempt.stage == Stage::Failed);
        assert!(attempt.installation.is_some());
        assert!(attempt.policy.is_some());
        assert!(matches!(
            attempt.failure,
            Some(ProviderError::Contract(ContractError::Invalid { .. }))
        ));
        assert!(attempt.handshake.is_none());
        assert!(attempt.registry.is_none());
        assert!(attempt.wrapper.is_none());
        let actual = attempt.retained_backing_data().unwrap();
        assert!(actual <= row[0]);
        assert!(attempt.construct_data(&launch, &selection, cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), actual);
    }

    #[test]
    fn expired_or_replaced_original_cut_and_foreign_roster_refuse_before_cloning() {
        for fault in 0..3 {
            let (launch, mut selection) = fixture(false);
            let original_cut = if fault == 0 {
                OperationalDeadline::expired_fixture()
            } else {
                cut()
            };
            let (mut attempt, _) = quoted(&launch, original_cut);
            let supplied_cut = if fault == 1 { cut() } else { original_cut };
            if fault == 2 {
                selection.0.clear();
            }

            assert!(
                attempt
                    .construct_data(&launch, &selection, supplied_cut)
                    .is_err()
            );

            assert!(attempt.stage == Stage::Failed);
            assert!(attempt.installation.is_none());
            assert!(attempt.policy.is_none());
            assert!(attempt.handshake.is_none());
            assert!(attempt.registry.is_none());
            assert!(attempt.wrapper.is_none());
            assert_eq!(attempt.retained_backing_data().unwrap(), 0);
            assert!(attempt.start_data(cut()).is_err());
        }
    }
}
