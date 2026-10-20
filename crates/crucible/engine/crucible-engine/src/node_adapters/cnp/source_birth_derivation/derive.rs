//! Runs the original pure derivation schedule on secret-free borrowed operands.
//!
//! Untrusted operands require an isolated process with an OS resource envelope.
//! Existing parsers, typed DTO constructors and serializers retain their ordinary
//! allocation, recursion and abort behavior. This facade is not an in-process
//! deep-safe parser or a Source admission mechanism. Its own retained DOM roots
//! retire iteratively; cleanup allocation failure terminates the contained child.
//!
//! The caller independently binds the expected original coordinator, deferred
//! origin disposition, projected launch and registration to one authenticated
//! job. These public data types prove none of those associations. Returned bytes
//! are ordinary candidate banks, never accepted banks or native authority.

use super::views::{RegistrationView, SourceBirthView};
use crate::{
    node_adapters::cnp::PacketCompleteAckHostRegistrationPlan, node_contract::NodeRuntime,
};
use crucible_node_format::canonical;
use crucible_node_transport::reference_packet::{
    coordinator::PacketNative5CoordinatorInstallation,
    service::{
        PacketNative5LaunchValidationProjection,
        complete_restore::import18::hello::{
            native_import18_hello_declaration_from_fields_data,
            native_import18_prospective_host_registration_from_fields_data,
        },
    },
};

#[path = "derive/error.rs"]
mod error;
#[path = "derive/output.rs"]
pub(crate) mod output;
#[path = "derive/retirement.rs"]
mod retirement;

pub use error::{DerivationCause, DerivationFailure, DerivationStage, WorldRefusal};
use output::ReservedWriter;
use retirement::RetainedValue;

/// Borrows the independently retained original or a deferred original-guard error.
///
/// This enum carries DATA, not an authenticated Source-world capability.
#[derive(Clone, Copy)]
pub enum ExpectedCoordinator<'a> {
    /// Borrows the complete producer's independently installed original.
    Producer(&'a PacketNative5CoordinatorInstallation),
    /// Borrows the reactive member's independently installed edition-five original.
    Reactive(&'a PacketNative5CoordinatorInstallation),
    /// Carries an original guard failure to its unchanged post-decode position.
    Deferred(WorldRefusal),
}

impl ExpectedCoordinator<'_> {
    fn compare(self, candidate: &PacketNative5CoordinatorInstallation) -> Result<(), WorldRefusal> {
        match self {
            Self::Producer(original) if original == candidate => Ok(()),
            Self::Reactive(original) if original == candidate => Ok(()),
            Self::Producer(_) => Err(WorldRefusal::ProducerCoordinatorChanged),
            Self::Reactive(_) => Err(WorldRefusal::ReactiveCoordinatorChanged),
            Self::Deferred(reason) => Err(reason),
        }
    }
}

/// Borrows all actual operands of one pure, once-only derivation call.
pub struct DerivationInput<'a> {
    /// Borrows nonsecret fields and exact opaque serialization shapes.
    pub launch: &'a PacketNative5LaunchValidationProjection<'a>,
    /// Borrows the independent original-world comparison operand or deferred error.
    pub expected: ExpectedCoordinator<'a>,
    /// Borrows the actual caller's planned registration operands.
    pub registration: &'a PacketCompleteAckHostRegistrationPlan,
}

/// Restricts requested output-bank storage independently of semantic validation.
#[derive(Clone, Copy)]
pub struct OutputLimits {
    /// Bounds the sum of both requested bank reservations and observed capacities.
    ///
    /// The OS envelope bounds parser/DOM/DTO work before this output-only check.
    pub maximum_output_bytes: usize,
}

/// Owns both ordinary canonical candidate byte banks after successful derivation.
#[derive(Debug)]
pub struct DerivedSourceBirth {
    source: Vec<u8>,
    registration: Vec<u8>,
    requested: [usize; 2],
}

impl DerivedSourceBirth {
    /// Borrows the canonical SourceBirth candidate bytes.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source
    }

    /// Borrows the canonical planned registration candidate bytes.
    pub fn registration_bytes(&self) -> &[u8] {
        &self.registration
    }

    /// Returns the actual geometry requests used by the original encoding step.
    pub fn requested_bank_bytes(&self) -> [usize; 2] {
        self.requested
    }

    /// Moves ordinary bytes out without issuing an accepted-bank capability.
    pub fn into_banks(self) -> (Vec<u8>, Vec<u8>) {
        (self.source, self.registration)
    }
}

/// Derives both candidate banks in the ordinary SourceBirth algorithm's order.
///
/// Launch validation includes its original first Coordinator decode and policy
/// repetitions. A distinct second decode precedes the independent original-world
/// comparison. Source/registration DOMs, Hello, prospective registration and both
/// canonical banks follow in their original order. A deferred expected-world
/// error never masks an earlier candidate failure.
///
/// # Errors
/// Returns the exact failed stage, owned underlying error and any written bank
/// prefixes. Output bounds and fallible reservations are operational failures,
/// distinct from the original semantic failures. Untrusted input must run inside
/// a contained child: stock parser/DTO/serializer aborts are not caught here.
pub fn derive_source_birth(
    input: DerivationInput<'_>,
    limits: OutputLimits,
) -> Result<DerivedSourceBirth, DerivationFailure> {
    let mut stage = DerivationStage::LaunchValidation;
    let mut source_bank = Vec::new();
    let mut registration_bank = Vec::new();
    let mut requested = [0; 2];

    let result = (|| -> Result<(), DerivationCause> {
        input
            .launch
            .validate_data()
            .map_err(DerivationCause::Provider)?;
        let fields = input.launch.fields_data();

        stage = DerivationStage::CoordinatorDecode;
        let coordinator = PacketNative5CoordinatorInstallation::decode(
            fields.initial_coordinator.bytes.as_slice(),
            fields.selection,
        )
        .map_err(DerivationCause::Provider)?;

        stage = DerivationStage::WorldComparison;
        input
            .expected
            .compare(&coordinator)
            .map_err(DerivationCause::World)?;

        stage = DerivationStage::SourceMaterialization;
        let [binding] = fields.selection.realization.bindings.as_slice() else {
            return Err(DerivationCause::World(WorldRefusal::AmbiguousBinding));
        };
        let source = RetainedValue::new(
            serde_json::to_value(SourceBirthView {
                fields,
                coordinator: &coordinator,
            })
            .map_err(DerivationCause::Json)?,
        );

        stage = DerivationStage::RegistrationMaterialization;
        // The ordinary consumer calls views() again before this second DOM.
        let [_] = fields.selection.realization.bindings.as_slice() else {
            return Err(DerivationCause::World(WorldRefusal::AmbiguousBinding));
        };
        let registration = RetainedValue::new(
            serde_json::to_value(RegistrationView {
                schema: "source-owned.packet-canonical-ack-registration/5",
                role: "controller",
                connection_id: &input.registration.connection_id,
                session_id: &binding.authority.session_id,
                incarnation_id: &binding.authority.incarnation_id,
                limits: fields.limits,
                features: &input.registration.features,
                extensions: &input.registration.extensions,
                envelope_extensions: &input.registration.envelope_extensions,
            })
            .map_err(DerivationCause::Json)?,
        );

        stage = DerivationStage::HelloDeclaration;
        let declaration = native_import18_hello_declaration_from_fields_data(&fields)
            .map_err(DerivationCause::Provider)?;
        stage = DerivationStage::ProspectiveRegistration;
        native_import18_prospective_host_registration_from_fields_data(
            &fields,
            &declaration,
            registration.value(),
            usize::MAX,
        )
        .map_err(DerivationCause::Provider)?;

        stage = DerivationStage::SourceGeometry;
        requested[0] =
            NodeRuntime::borrowed_serialization_geometry_data(source.value(), usize::MAX)
                .map_err(DerivationCause::Runtime)?
                .1;
        stage = DerivationStage::RegistrationGeometry;
        requested[1] =
            NodeRuntime::borrowed_serialization_geometry_data(registration.value(), usize::MAX)
                .map_err(DerivationCause::Runtime)?
                .1;

        stage = DerivationStage::OutputReservation;
        let total = requested[0]
            .checked_add(requested[1])
            .ok_or(DerivationCause::OutputOverflow)?;
        if total > limits.maximum_output_bytes {
            return Err(DerivationCause::OutputLimit);
        }
        for (bank, extent) in [
            (&mut source_bank, requested[0]),
            (&mut registration_bank, requested[1]),
        ] {
            bank.try_reserve_exact(extent)
                .map_err(DerivationCause::Reservation)?;
            // Preserve the ordinary constructor's actual-capacity refusal.
            if bank.capacity() > extent {
                return Err(DerivationCause::OutputCapacity);
            }
        }

        stage = DerivationStage::SourceEncoding;
        canonical::canonical_json_to_writer(
            source.value(),
            &mut ReservedWriter {
                bank: &mut source_bank,
                maximum: requested[0],
            },
        )
        .map_err(DerivationCause::Contract)?;
        stage = DerivationStage::RegistrationEncoding;
        canonical::canonical_json_to_writer(
            registration.value(),
            &mut ReservedWriter {
                bank: &mut registration_bank,
                maximum: requested[1],
            },
        )
        .map_err(DerivationCause::Contract)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(DerivedSourceBirth {
            source: source_bank,
            registration: registration_bank,
            requested,
        }),
        Err(cause) => Err(DerivationFailure {
            stage,
            cause,
            source_bank,
            registration_bank,
        }),
    }
}
