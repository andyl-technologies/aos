//! Borrows every retained endpoint Commit-flight field as inert history.
//!
//! ```json
//! {"schema":"source-private.endpoint-restore-commit-flight/17","mapping_role":"native-archived-protocol-mapping","admission":null,"held":null,"proof":null,"recovered_connection":null,"completed":null,"proof_charge":0,"proof_allocation":null}
//! ```
//!
//! Unsupported active publication capsules refuse before any owner is moved.
//! Independently present completed and recovered fields remain independently
//! present; serializing a historical flight never creates native installation.

use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::Native5Policy;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct FlightHistory<'a> {
    flight: &'a RestoreCommitFlight<DeadlineStream>,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    policy: &'a Rc<Native5Policy>,
}

impl RestoreCommitFlight<DeadlineStream> {
    fn authenticate_settled17_roots_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<Native5Policy>,
    ) -> Result<(), ProviderError> {
        // The live proof capsule can own an unwinding callback and transport.
        // Refusal leaves that exact capsule beside the original flight.
        if self.proof.is_some() {
            return Err(ProviderError::Correlation(
                "native17 active endpoint proof unsupported",
            ));
        }
        let owner = boot.try_borrow().map_err(|_| refused())?;
        owner.authenticate_settled17_policy_data(policy)?;
        drop(owner);
        if let Some(admission) = &self.admission {
            admission.authenticate_settled17_roots_data(
                boot,
                policy,
                self.mapping.as_ref().ok_or_else(refused)?,
            )?;
        }
        if let Some(held) = &self.held {
            held.authenticate_settled17_roots_data(
                boot,
                self.mapping.as_ref().ok_or_else(refused)?,
            )?;
        }
        Ok(())
    }

    /// Borrows the exact retained fields and authenticates their real role edges.
    ///
    /// # Errors
    /// Refuses a live publication proof, borrowed native root or changed token
    /// relation while preserving every retained field in this flight.
    pub(crate) fn borrowed_settled17_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        policy: &'a Rc<Native5Policy>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.authenticate_settled17_roots_data(boot, policy)?;
        Ok(FlightHistory {
            flight: self,
            boot,
            policy,
        })
    }

    /// Observes all independently present field capacities and real alias edges.
    ///
    /// # Errors
    /// Refuses unsupported active proof, changed roots or exhausted record banks.
    pub(crate) fn observe_settled17_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<Native5Policy>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled17_roots_data(boot, policy)?;
        let Self {
            mapping,
            admission,
            held,
            proof: _,
            recovered_connection,
            completed,
            proof_charge,
            proof_allocation,
        } = self;
        if let Some(mapping) = mapping {
            observer.shared_original(MetadataSharedKind::ArchivedMapping, mapping.as_ref())?;
        }
        if let Some(admission) = admission {
            admission.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(held) = held {
            held.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(connection) = recovered_connection {
            connection.observe_native_settled17_metadata(observer)?;
        }
        if let Some(completed) = completed {
            completed.observe_settled17_metadata_data(observer)?;
        }
        observer.observe(proof_charge)?;
        if let Some(quote) = proof_allocation {
            quote.observe_settled_history_metadata_data(observer)?;
        }
        Ok(())
    }

    /// Counts the actual borrowed flight and serializer/token view headers.
    pub(crate) fn settled17_counter_scratch_data() -> usize {
        std::mem::size_of::<FlightHistory<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + VerifiedCompleteRestoration::settled_history_counter_scratch_data()
            + VerifiedCompleteRestorationHeld::settled_history_counter_scratch_data()
            + OriginalRestoreHeldProofAllocationQuote::settled_history_counter_scratch_data()
    }
}

impl Serialize for FlightHistory<'_> {
    fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        self.flight
            .authenticate_settled17_roots_data(self.boot, self.policy)
            .map_err(serde::ser::Error::custom)?;
        let RestoreCommitFlight {
            mapping,
            admission,
            held,
            proof: _,
            recovered_connection,
            completed,
            proof_charge,
            proof_allocation,
        } = self.flight;
        let mut fields = serializer.serialize_struct("EndpointRestoreCommitFlight17", 9)?;
        fields.serialize_field("schema", "source-private.endpoint-restore-commit-flight/17")?;
        fields.serialize_field(
            "mapping_role",
            &mapping.as_ref().map(|_| "native-archived-protocol-mapping"),
        )?;
        fields.serialize_field(
            "admission",
            &admission
                .as_ref()
                .map(VerifiedCompleteRestoration::borrowed_settled_history_data)
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "held",
            &held
                .as_ref()
                .map(VerifiedCompleteRestorationHeld::borrowed_settled_history_data)
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("proof", &Option::<()>::None)?;
        fields.serialize_field(
            "recovered_connection",
            &recovered_connection
                .as_ref()
                .map(Connection::borrowed_native_settled17_data)
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "completed",
            &completed
                .as_ref()
                .map(ExchangeRecord::original_protocol_view),
        )?;
        fields.serialize_field("proof_charge", proof_charge)?;
        fields.serialize_field(
            "proof_allocation",
            &proof_allocation
                .as_ref()
                .map(OriginalRestoreHeldProofAllocationQuote::borrowed_settled_history_data)
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.end()
    }
}

use crate::connection::{
    HistoricalCurrentNativeConnection17, HistoricalExchangeRecord17, NativeConnection17GroupIds,
};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::service::ack_emitter::{
    HistoricalCommitToken17, HistoricalHeldToken17,
};
use crate::retained_metadata::records::MetadataRecordKind;

/// Retains actual same-pass shared-role coordinates from an endpoint flight.
#[derive(Clone, Copy, Default)]
pub(crate) struct RestoreCommitFlight17Groups {
    pub(crate) mapping: Option<usize>,
    pub(crate) admission: Option<(usize, usize, usize, usize, usize)>,
    pub(crate) held: Option<(usize, usize, usize, usize)>,
    pub(crate) recovered: Option<NativeConnection17GroupIds>,
    pub(crate) completed: Option<(usize, usize)>,
    pub(crate) proof_allocation: Option<(usize, usize, usize)>,
}

/// Owns retained flight DATA without a transport, proof publisher or held token.
pub(crate) struct HistoricalRestoreCommitFlight17 {
    pub(crate) admission: Option<HistoricalCommitToken17>,
    pub(crate) held: Option<HistoricalHeldToken17>,
    pub(crate) recovered_connection: Option<HistoricalCurrentNativeConnection17>,
    pub(crate) completed: Option<HistoricalExchangeRecord17>,
    pub(crate) proof_charge: usize,
    pub(crate) proof_allocation: Option<HistoricalProofAllocation17>,
    groups: RestoreCommitFlight17Groups,
}

/// Preserves the exact retained proof-allocation scalars without prebuild rights.
pub(crate) struct HistoricalProofAllocation17 {
    pub(crate) maximum_frames: usize,
    pub(crate) requested_bytes: usize,
    pub(crate) prebuilding: bool,
    groups: (usize, usize, usize),
}

impl HistoricalRestoreCommitFlight17 {
    /// Checks all independently present fields with one caller-owned ledger.
    ///
    /// # Errors
    /// Refuses active publication proof, changed field framing or alias roots.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }

    /// Returns actual role coordinates during both validation and construction.
    ///
    /// # Errors
    /// Refuses unsupported active proof, changed field framing or alias roots.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, RestoreCommitFlight17Groups), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.endpoint-restore-commit-flight/17",
        )?;
        let mapping = fields.named("mapping_role")?;
        let mapping = if mapping == b"null" {
            None
        } else {
            exact(mapping, "native-archived-protocol-mapping")?;
            Some(shared_reference_data::<
                RefCell<PreparedArchivedNativeProtocolMapping>,
            >(ledger, MetadataSharedKind::ArchivedMapping)?)
        };
        let admission_view = fields.named("admission")?;
        let (admission, admission_groups) = if admission_view == b"null" {
            (None, None)
        } else {
            let (owner, groups) =
                HistoricalCommitToken17::read_settled17_fields_data(admission_view, ledger, build)?;
            (owner, Some(groups))
        };
        let held_view = fields.named("held")?;
        let (held, held_groups) = if held_view == b"null" {
            (None, None)
        } else {
            let (owner, groups) =
                HistoricalHeldToken17::read_settled17_fields_data(held_view, ledger, build)?;
            (owner, Some(groups))
        };
        if fields.named("proof")? != b"null" {
            return Err(invalid());
        }
        let recovered_view = fields.named("recovered_connection")?;
        let (recovered_connection, recovered_groups) = if recovered_view == b"null" {
            (None, None)
        } else {
            let (owner, groups) = crate::connection::read_native17_connection_fields_data(
                recovered_view,
                ledger,
                build,
            )?;
            (owner, Some(groups))
        };
        let completed_view = fields.named("completed")?;
        let (completed, completed_groups) = if completed_view == b"null" {
            (None, None)
        } else {
            HistoricalExchangeRecord17::read_settled17_fields_data(completed_view, ledger, build)?
        };
        let proof_charge = ledger
            .read::<usize>(fields.named("proof_charge")?, true)?
            .ok_or_else(invalid)?;
        let proof_allocation_view = fields.named("proof_allocation")?;
        let proof_allocation = if proof_allocation_view == b"null" {
            None
        } else {
            Some(HistoricalProofAllocation17::read_settled17_data(
                proof_allocation_view,
                ledger,
            )?)
        };
        fields.finish()?;
        if let Some((_, held_mapping, _, _)) = held_groups {
            if mapping != Some(held_mapping) {
                return Err(invalid());
            }
        }
        if admission_groups.is_some() && mapping.is_none() {
            return Err(invalid());
        }
        let groups = RestoreCommitFlight17Groups {
            mapping,
            admission: admission_groups,
            held: held_groups,
            recovered: recovered_groups,
            completed: completed_groups,
            proof_allocation: proof_allocation.as_ref().map(|quote| quote.groups),
        };
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                admission,
                held,
                recovered_connection,
                completed,
                proof_charge,
                proof_allocation,
                groups,
            }),
            groups,
        ))
    }

    /// Returns real same-pass mapping, token, recovered and proof allocation edges.
    pub(crate) const fn group_ids_data(&self) -> RestoreCommitFlight17Groups {
        self.groups
    }
}

impl HistoricalType for HistoricalRestoreCommitFlight17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

impl HistoricalProofAllocation17 {
    fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.restore-proof-quote-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor = shared_reference_data::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        exact(fields.named("codec_role")?, "native-connection-codec")?;
        let codec = shared_reference_data::<crate::connection::Native5CodecOwner>(
            ledger,
            MetadataSharedKind::Codec,
        )?;
        exact(fields.named("bank_role")?, "native-connection-frames")?;
        let bank = shared_reference_data::<
            RefCell<crate::transport::original_frames::OriginalFrameReservation>,
        >(ledger, MetadataSharedKind::FrameBank)?;
        let maximum_frames = ledger
            .read::<usize>(fields.named("maximum_frames")?, true)?
            .ok_or_else(invalid)?;
        let requested_bytes = ledger
            .read::<usize>(fields.named("requested_bytes")?, true)?
            .ok_or_else(invalid)?;
        let prebuilding = ledger
            .read::<bool>(fields.named("prebuilding")?, true)?
            .ok_or_else(invalid)?;
        fields.finish()?;
        Ok(Self {
            maximum_frames,
            requested_bytes,
            prebuilding,
            groups: (actor, codec, bank),
        })
    }
}

fn shared_reference_data<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, std::mem::align_of::<T>())?
        != std::mem::size_of::<T>()
    {
        return Err(invalid());
    }
    ledger.shared_reference(kind, std::mem::size_of::<T>())
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
