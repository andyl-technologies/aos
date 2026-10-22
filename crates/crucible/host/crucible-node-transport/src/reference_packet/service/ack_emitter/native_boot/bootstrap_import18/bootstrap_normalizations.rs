//! Constructs the five bootstrap normalization hashes from original guarded DATA.
//!
//! One external attempt retains its current Value/hash state and every computed
//! digest across refusal. Successful role observation precedes releasing that
//! role's disposable banks. The original receiver also spends its occurrence.
//! Actual admission belongs to the enclosing owner; these DATA constructors issue
//! no opaque Initial/Recipe, Source/Birth credit, ACK or native phase permission.

use super::bootstrap_operands::BootstrapAckOperands;
use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18DecodedBodyLoans;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_registration_counter_scratch_data;

#[path = "bootstrap_normalizations/hash_sink.rs"]
mod hash_sink;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use crate::retained_metadata::{
    BootstrapBodyMetadataProfileData, MetadataObserver, RetainedProtocolMetadataFacts,
    requested_metadata_backing_storage_data,
};
use crucible_node_format::{ContractError, canonical};
use hash_sink::HashSink;

#[path = "bootstrap_normalizations/value_backing.rs"]
mod value_backing;
use serde::Serialize;
use serde_json::Value;
use std::rc::{Rc, Weak};

/// Names only the closed normalization schedule, never a native phase claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Role {
    /// Normalizes the complete original birth association.
    Birth,
    /// Normalizes actual controller and measured native kernel identities.
    Kernel,
    /// Normalizes the original immutable policy and current negotiated selection.
    Policy,
    /// Normalizes the original actual native registration.
    NativeRegistration,
    /// Canonicalizes the already retained complete Host registration Value.
    HostRegistration,
}

impl Role {
    const ALL: [Self; 5] = [
        Self::Birth,
        Self::Kernel,
        Self::Policy,
        Self::NativeRegistration,
        Self::HostRegistration,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Birth => 0,
            Self::Kernel => 1,
            Self::Policy => 2,
            Self::NativeRegistration => 3,
            Self::HostRegistration => 4,
        }
    }
}

/// Retains computed normalization hashes without granting their receipt or use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct Digests {
    /// Commits the complete original six-field birth association.
    pub(in super::super) birth: [u8; 32],
    /// Commits both complete kernel roles.
    pub(in super::super) kernel: [u8; 32],
    /// Commits the complete original selected policy.
    pub(in super::super) policy: [u8; 32],
    /// Commits all nine actual native registration fields.
    pub(in super::super) native_registration: [u8; 32],
    /// Commits the original complete planned Host registration.
    pub(in super::super) host_registration: [u8; 32],
}

/// Observes both actual owners before allocation and after either role outcome.
pub(in super::super) trait Admission {
    /// Admits the stored component row while observing both original owners.
    ///
    /// The caller independently funds callbacks and retains their returned errors.
    ///
    /// # Errors
    /// Refuses unavailable original credit or an incomplete whole-owner census.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Admits a single reserved role before either serializer or canonical writer.
    ///
    /// # Errors
    /// Refuses unavailable credit, changed original custody or role admission.
    fn role_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
    ) -> Result<(), ProviderError>;

    /// Observes surviving actual banks before releasing any successful role output.
    ///
    /// This callback also runs after serializer, canonical or terminal refusal.
    ///
    /// # Errors
    /// Refuses incomplete observation or actual whole-owner demand above credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains one normalization occurrence and its actual partial output ownership.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    role: Option<Role>,
    finished: usize,
    value: Option<Value>,
    hash: HashSink,
    value_profile: Option<BootstrapBodyMetadataProfileData>,
    digests: [Option<[u8; 32]>; 5],
}

impl Attempt {
    /// Initializes empty slots; the caller retains and funds this inline header.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            role: None,
            finished: 0,
            value: None,
            hash: HashSink::empty_data(),
            value_profile: None,
            digests: [None; 5],
        }
    }

    fn bind(&mut self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError> {
        self.cut = Some(original.cut);
        self.launch = Some(Rc::downgrade(original.parsed.shared_launch_data()?));
        Ok(())
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = &self.launch
            && !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            )
        {
            return Err(refused());
        }
        Ok(())
    }

    fn guard(
        &self,
        original: &OriginalImport18RawBootstrap,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        self.authenticate_alias(original)?;
        original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }

    /// Counts this actual header and surviving banks, including after refusal.
    ///
    /// The checked Weak edge aliases the same original launch allocation. Its
    /// control block is already counted by the original retained decoder.
    ///
    /// # Errors
    /// Refuses foreign launch association, metadata traversal or checked overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        let mut observer = MetadataObserver::new();
        if let Some(value) = &self.value {
            let profile = self.value_profile.ok_or_else(refused)?;
            observer
                .with_bootstrap_body_profile_data(profile, |observer| observer.observe(value))?;
        }
        size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(exhausted)
    }

    fn serialize(
        &mut self,
        value: &impl Serialize,
        maximum: usize,
        role: Role,
    ) -> Result<(), ProviderError> {
        self.value = Some(serde_json::to_value(value).map_err(ContractError::from)?);
        let value = self.value.as_ref().ok_or_else(refused)?;
        canonical::canonical_json_to_writer(value, &mut self.hash)?;
        self.finish_hash(maximum, role)
    }

    fn canonicalize_host(&mut self, value: &Value, maximum: usize) -> Result<(), ProviderError> {
        // The original decoder already retains this Value. Do not clone it.
        canonical::canonical_json_to_writer(value, &mut self.hash)?;
        self.finish_hash(maximum, Role::HostRegistration)
    }

    fn finish_hash(&mut self, maximum: usize, role: Role) -> Result<(), ProviderError> {
        if self.hash.refused || self.hash.written == 0 || self.hash.written > maximum {
            return Err(exhausted());
        }
        self.digests[role.index()] = Some(*self.hash.hasher.finalize().as_bytes());
        Ok(())
    }

    /// Borrows only completed computed hashes under the same original guards.
    ///
    /// The values authenticate no proof, receipt, Host plan or Source/Birth grant.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction or stale original inputs and SDK.
    pub(in super::super) fn digests_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<Digests, ProviderError> {
        self.with_completed_digests_data(original, |_, digests| Ok(digests))
    }

    fn with_completed_digests_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        inspect: impl FnOnce(&BootstrapAckOperands<'_>, Digests) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed || self.finished != 5 || self.value.is_some() {
            return Err(refused());
        }
        original.with_bootstrap_ack_operands_data(|operands| {
            self.guard(original, operands)?;
            let [
                Some(birth),
                Some(kernel),
                Some(policy),
                Some(native_registration),
                Some(host_registration),
            ] = self.digests
            else {
                return Err(refused());
            };
            let outcome = inspect(
                operands,
                Digests {
                    birth,
                    kernel,
                    policy,
                    native_registration,
                    host_registration,
                },
            );
            let terminal = self.guard(original, operands);
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }

    /// Lends the five computed hashes after checking the complete original Host plan.
    ///
    /// The original launch, nine-field controller plan and actual native SDK
    /// must agree. Plan, channel, cut and SDK guards surround either callback
    /// outcome. The callback and its Copy result are independently funded.
    /// This comparison issues no controller connection, Source grant or ACK.
    ///
    /// # Errors
    /// Refuses incomplete hashes, a foreign original owner, malformed or changed
    /// Host plan, stale custody/SDK/cut, callback refusal or a terminal failure.
    pub(in super::super) fn with_host_bound_digests_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        inspect: impl FnOnce(Digests) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_host_bound_operands_data(original, |_, digests| inspect(digests))
    }

    /// Lends the same already guarded SDK operands for a composite DATA phase.
    ///
    /// The full original loan remains open around the entire callback. Its
    /// borrowed authority can recheck revocation between separately admitted
    /// operations without reconstructing the immutable original custody chain.
    ///
    /// # Errors
    /// Preserves every original/Host/SDK, callback and terminal refusal.
    pub(super) fn with_host_bound_operands_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        inspect: impl FnOnce(&BootstrapAckOperands<'_>, Digests) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_completed_digests_data(original, |operands, digests| {
            let bodies = original.typed_bodies_data()?;
            let launch = bodies.launch.launch_data();
            let declaration = original.hello_declaration.as_ref().ok_or_else(refused)?;
            let planned = bodies.boot.expected_host_registration_data();
            operands.authenticate_host_plan_data(launch, declaration, planned)?;

            let outcome = inspect(operands, digests);
            let terminal = operands.authenticate_host_plan_data(launch, declaration, planned);
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }

    /// Quotes the actual nested loans and Host comparison for a concrete Copy result.
    ///
    /// Dynamic callback storage remains an independent enclosing admission.
    ///
    /// # Errors
    /// Refuses checked accumulation overflow.
    pub(in super::super) fn host_loan_counter_scratch_data<R: Copy>() -> Result<usize, ProviderError>
    {
        [
            native_import18_registration_counter_scratch_data(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<&Self>(),
            size_of::<&OriginalImport18RawBootstrap>(),
            size_of::<Digests>() * 2,
            size_of::<Result<Digests, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<(), ProviderError>>() * 3,
            size_of::<OriginalImport18DecodedBodyLoans<'static>>(),
            size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>(),
            size_of::<&PacketNative5SourceLaunch>(),
            size_of::<&PacketNativeImport18HelloDeclarationData>(),
            size_of::<&Value>(),
            size_of::<Option<&PacketNativeImport18HelloDeclarationData>>(),
        ]
        .into_iter()
        .try_fold(
            OriginalImport18RawBootstrap::bootstrap_ack_operands_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }
}

impl OriginalImport18RawBootstrap {
    /// Normalizes original bootstrap DATA once, preserving every failed output.
    ///
    /// Both the receiver and the external attempt spend their occurrences before
    /// the first guard. The caller retains that attempt alongside the actual
    /// receiver. The aggregate holds raw/typed/policy data immutably; each role
    /// separately checks the current channel, cut, SDK and original launch alias.
    /// Full original guards run around either aggregate callback outcome.
    ///
    /// # Errors
    /// Refuses retry, incomplete originals, short credit, serialization, JCS,
    /// changed custody/SDK/cut or any failed terminal whole-owner observation.
    pub(in super::super) fn construct_bootstrap_normalizations_data(
        &mut self,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_normalizations_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_normalizations_started = true;
        attempt.started = true;
        let outcome = self.with_bootstrap_ack_operands_data(|operands| {
            attempt.bind(self)?;
            self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
            let host = self
                .typed_bodies_data()?
                .boot
                .expected_host_registration_data();
            let mut host_shape = Projection::new(usize::MAX)?;
            host_shape.add_value(host)?;
            let [birth, kernel, policy, registration] =
                operands.serialization_shapes_data(usize::MAX)?;
            let shapes = [
                birth,
                kernel,
                policy,
                registration,
                host_shape.finish(usize::MAX)?,
            ];
            let row = construction_data(&shapes, self.bounds.requested_peak)?;
            attempt.row = Some(row);
            let mut whole = row;
            whole[0] = whole[0]
                .checked_add(self.retained_requested_bytes()?)
                .ok_or_else(exhausted)?;
            self.admit_source_row(whole)?;
            admission.construct_data(self, attempt, row)?;
            attempt.guard(self, operands)?;

            for role in Role::ALL {
                attempt.role = Some(role);
                admission.role_data(self, attempt, role)?;
                attempt.guard(self, operands)?;
                let shape = &shapes[role.index()];
                let maximum = shape.maximum_encoded_bytes;
                attempt.hash.begin_data(maximum);
                if role != Role::HostRegistration {
                    attempt.value_profile = Some(
                        BootstrapBodyMetadataProfileData::from_strict_value_populations_data(
                            shape.serialized_value_nodes,
                            shape.serialized_value_nodes,
                        )?,
                    );
                }
                let constructed = match role {
                    Role::Birth => attempt.serialize(operands.birth, maximum, role),
                    Role::Kernel => attempt.serialize(operands.kernel, maximum, role),
                    Role::Policy => attempt.serialize(operands.policy, maximum, role),
                    Role::NativeRegistration => {
                        attempt.serialize(operands.registration, maximum, role)
                    }
                    Role::HostRegistration => attempt.canonicalize_host(host, maximum),
                };
                let terminal = attempt.guard(self, operands);
                let census = attempt
                    .retained_requested_bytes_data(self)
                    .and_then(|actual| admission.finish_data(self, attempt, role, actual));
                let observed = attempt.guard(self, operands);
                constructed?;
                terminal?;
                census?;
                observed?;
                attempt.finished += 1;
                attempt.value = None;
                attempt.hash = HashSink::empty_data();
                attempt.value_profile = None;
            }
            Ok(())
        });
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }
}

/// Quotes actual simultaneous owner backing and sequential normalization work.
///
/// The fifth role borrows the already retained Host Value. Other roles retain
/// their actual Value through census. Canonical bytes feed the inline hash sink;
/// there is no output bank. Conservative DOM/JCS scratch remains intact and no
/// JSON parser is run here.
/// These numeric bounds supply no admission or opaque funding result.
///
/// # Errors
/// Refuses checked arithmetic overflow or the complete row above the restriction.
pub(in crate::reference_packet::service) fn construction_data(
    shapes: &[Shape; 5],
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = [
        size_of::<Attempt>(),
        size_of::<Attempt>() + size_of::<Result<Attempt, ProviderError>>(),
        counter_scratch_data()?,
    ];
    for (index, shape) in shapes.iter().enumerate() {
        let value = if index == Role::HostRegistration.index() {
            0
        } else {
            value_backing::requested_data(shape)?
        };
        row[0] = row[0].max(
            size_of::<Attempt>()
                .checked_add(value)
                .ok_or_else(exhausted)?,
        );
        row[1] = row[1].max(
            shape
                .dom_and_canonical_scratch_bytes
                .checked_add(shape.serializer_temporary_requested_bytes)
                .ok_or_else(exhausted)?,
        );
        row[2] = row[2].max(
            counter_scratch_data()?
                .checked_add(shape.declared_counter_scratch_bytes)
                .ok_or_else(exhausted)?,
        );
    }
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

/// Names actual normalization, canonical, hash, metadata and original loan controls.
///
/// # Errors
/// Refuses checked accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    [
        original_serialization_counter_scratch_data(),
        value_backing::serializer_counter_scratch_data()?,
        canonical::canonical_json_counter_scratch_bytes_data(),
        size_of::<Attempt>(),
        size_of::<&mut Attempt>(),
        size_of::<&Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<[Shape; 5]>(),
        size_of::<Result<[Shape; 5], ProviderError>>(),
        size_of::<Projection>(),
        size_of::<MetadataObserver>(),
        size_of::<RetainedProtocolMetadataFacts>(),
        size_of::<Value>(),
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<HashSink>(),
        size_of::<&mut HashSink>(),
        size_of::<std::io::Result<usize>>(),
        size_of::<Result<(), ContractError>>(),
        size_of::<BootstrapBodyMetadataProfileData>(),
        size_of::<Result<BootstrapBodyMetadataProfileData, ProviderError>>(),
        BootstrapBodyMetadataProfileData::from_strict_value_populations_data(1, 0)?
            .walk_scratch_data()?,
        size_of::<blake3::Hasher>(),
        size_of::<blake3::Hash>(),
        size_of::<Digests>(),
        size_of::<[usize; 3]>() * 3,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<Result<Digests, ProviderError>>(),
        size_of::<Result<(), ProviderError>>() * 5,
        size_of::<Option<usize>>(),
        size_of::<[usize; 4]>(),
        crate::retained_metadata::serialization_storage::original_serialization_tree_node_counter_scratch_data(),
        size_of::<Role>(),
        size_of::<std::array::IntoIter<Role, 5>>(),
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
        size_of::<Result<usize, ProviderError>>(),
        size_of::<std::slice::Iter<'static, Shape>>(),
    ]
    .into_iter()
    .try_fold(
        OriginalImport18RawBootstrap::bootstrap_ack_operands_counter_scratch_data::<Digests>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
    .and_then(|construction| {
        // Completed Host inspection is sequential with allocating normalization.
        let host_loan = Attempt::host_loan_counter_scratch_data::<Digests>()?;
        Ok(construction.max(host_loan))
    })
}

#[cfg(test)]
#[path = "bootstrap_normalizations/tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "bootstrap_normalizations/host_tests.rs"]
pub(super) mod host_tests;
