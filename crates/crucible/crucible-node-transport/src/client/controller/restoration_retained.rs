//! Observes actual Transfer12 owners without weakening the old complete reader.
//!
//! A partially assigned Prepare or Commit remains an owning state even when its
//! original physical deadline has expired. This raw census visits those exact
//! fields without requiring completion, publishing, decoding, renewing a cut or
//! issuing restoration permission. The old edition11 observer is unchanged.

use super::*;
use crate::{
    connection::{OriginalProtocolSupervisor, OriginalRetainedSupervisor},
    protocol_snapshot::{ProtocolCaptureOwner, RetainedProtocolMetadataFacts},
    retained_metadata::{MetadataObserver, aliases::MetadataSharedKind},
};
use std::mem::size_of;
use std::rc::Rc;

type AssignedFieldViews<'a> = (
    &'a Envelope,
    &'a Vec<u8>,
    &'a assigned_restore::Phase,
    &'a Option<Envelope>,
    &'a ContentRef,
    &'a Rc<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>,
);

struct Fields<'a> {
    session: &'a ClientSession,
    custody: &'a ClientCustody,
    route: &'a ControllerRoute,
    fenced: &'a bool,
    protocol_owner: &'a Rc<ProtocolCaptureOwner>,
    admit: &'a Option<assigned_admit::AssignedOriginalCanonicalAckAdmit>,
    prepare: &'a Option<assigned_restore::AssignedOriginalCompleteRestore>,
    commit: &'a Option<assigned_restore::AssignedOriginalCompleteRestore>,
    activation:
        &'a [Option<installed_activation::AssignedOriginalInstalledRestorationActivation>; 2],
    uploads: &'a [Option<installed_activation::AssignedUpload>; 2],
    observation: &'a Option<installed_observation::AssignedOriginalInstalledRestorationObservation>,
}

impl<'a> Fields<'a> {
    fn borrow(controller: &'a CnpController) -> Result<Self, ProviderError> {
        let CnpController {
            session,
            custody,
            route,
            budget: _,
            fenced,
            protocol_owner,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
            original_restored_settled_capture,
        } = controller;
        if original_complete_restore.is_some()
            || installed_complete_restore.is_some()
            || original_restored_settled_capture.is_some()
        {
            return Err(ProviderError::Correlation(
                "selected transfer raw owner class differs",
            ));
        }
        Ok(Self {
            session,
            custody,
            route,
            fenced,
            protocol_owner,
            admit: original_ack_admit,
            prepare: original_complete_restore_prepare,
            commit: original_complete_restore_commit,
            activation: original_installed_restoration_activation,
            uploads: original_installed_restoration_upload,
            observation: original_installed_restoration_observation,
        })
    }

    fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.observe(&self.route.node)?;
        observer.observe(&self.route.execution_owner)?;
        observer.observe(self.fenced)?;
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            self.protocol_owner.as_ref(),
        )?;
        self.session
            .observe_original_restoration_metadata(observer)?;
        self.custody.observe_owned_metadata(observer)?;
        if let Some(admit) = self.admit {
            admit.observe_owned_metadata(observer)?;
        }
        for original in [self.prepare.as_ref(), self.commit.as_ref()]
            .into_iter()
            .flatten()
        {
            observe_assigned(original, observer)?;
        }
        for original in self.uploads.iter().flatten() {
            original.observe_owned_metadata(observer)?;
        }
        for original in self.activation.iter().flatten() {
            original.observe_owned_metadata(observer)?;
        }
        if let Some(original) = self.observation {
            original.observe_owned_metadata(observer)?;
        }
        Ok(())
    }
}

// The selected raw observer deliberately does not call validate_owned_snapshot:
// an unsigned, sealing or publishing failure retains the same original owners.
fn observe_assigned(
    assigned: &assigned_restore::AssignedOriginalCompleteRestore,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let assigned_restore::AssignedOriginalCompleteRestore {
        original,
        bytes,
        literal_slot: _,
        cut: _,
        phase,
        response,
        mapping,
        mapping_identity,
        nonce: _,
    } = assigned;
    match phase {
        assigned_restore::Phase::Unsigned
        | assigned_restore::Phase::Sealing
        | assigned_restore::Phase::Sealed
        | assigned_restore::Phase::Publishing
        | assigned_restore::Phase::Complete => {}
    }
    observer.observe(original)?;
    observer.vector::<u8>(bytes.capacity())?;
    observer.observe(response)?;
    observer.observe(mapping)?;
    observer.shared_original(
        MetadataSharedKind::ArchivedMapping,
        mapping_identity.as_ref(),
    )
}

impl CnpController {
    /// Observes the original controller retained behind the compact boundary.
    ///
    /// The compact constructor excludes future operation assignments, and its
    /// opaque owner never exposes a mutable legacy controller. This raw walk
    /// preserves registration/codec identity after fencing or revocation;
    /// ownership observation cannot renew an effect permission.
    pub(super) fn observe_compact_runtime_legacy_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Fields::borrow(self)?.observe(observer)
    }

    /// Names actual raw transfer field, observer and partial-state cursor views.
    ///
    /// This includes the old direct-supervisor counter and the additional exact
    /// selected field view. Caller-owned inline Controller/Option roots, compiler
    /// or recursive frames and physical allocator overhead remain separate.
    pub fn original_restoration_host_metadata_counter_scratch_data() -> usize {
        Self::original_live_host_metadata_counter_scratch_data()
            + Self::original_installed_restoration_activation_counter_scratch_data()
            + Self::original_installed_restoration_upload_counter_scratch_data()
            + Self::original_installed_restoration_observation_counter_scratch_data()
            + ClientSession::original_restoration_metadata_counter_scratch_data()
            + size_of::<Fields<'static>>()
            + size_of::<Result<Fields<'static>, ProviderError>>()
            + size_of::<[Option<&assigned_restore::AssignedOriginalCompleteRestore>; 2]>()
            + size_of::<
                std::iter::Flatten<
                    std::array::IntoIter<
                        Option<&assigned_restore::AssignedOriginalCompleteRestore>,
                        2,
                    >,
                >,
            >()
            + size_of::<AssignedFieldViews<'static>>()
            + size_of::<&assigned_restore::AssignedOriginalCompleteRestore>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Counts real selected transfer partials beside their same known supervisor.
    ///
    /// With no assigned transfer, delegates to the unchanged original live-host
    /// walk. Once a dedicated Prepare or Commit slot exists, visits its real
    /// Transfer12 owning fields without authenticating a new live action. Every actual
    /// original, spare encoded bank, optional response and mapping association is walked
    /// independently. Phase or expiry never turns a retained owner into zero.
    /// No serializer, allocation, IO or erased callback runs, and these DATA facts
    /// supply no source capability, transfer action or final restoration context.
    ///
    /// # Errors
    /// Refuses another creator, a legacy/full installed
    /// archive owner, unknown supervisor/loss callback, busy actual owner or
    /// checked metadata traversal overflow.
    pub fn original_restoration_host_metadata_facts_with_retained_supervisor(
        &self,
        owner: &OriginalRetainedSupervisor,
        witness: Option<&OriginalProtocolSupervisor>,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.original_complete_restore_prepare.is_none()
            && self.original_complete_restore_commit.is_none()
        {
            return self.original_live_host_metadata_facts_with_retained_supervisor(owner, witness);
        }
        // These two private slots are filled only by prepare_transfer after
        // its actual Transfer12 mapping/emitter gates. Reading their real
        // fields is DATA, not renewed codec/registration or effect authority.
        // In particular, do not call the live codec predicates here: fenced
        // failure can still retain every one of these owning fields.
        self.session
            .authenticate_original_retained_supervisor_data(owner)?;
        if let Some(witness) = witness {
            self.session
                .authenticate_original_protocol_supervisor_data(witness)?;
        }
        let fields = Fields::borrow(self)?;
        let mut observer = MetadataObserver::new();
        fields.observe(&mut observer)?;
        self.session
            .observe_original_restoration_metadata_extras(&mut observer)?;
        owner.observe_retained_metadata(&mut observer)?;
        if let Some(witness) = witness {
            witness.observe_original_header(&mut observer)?;
            witness.observe_original_actor(&mut observer)?;
        }
        self.session
            .authenticate_original_retained_supervisor_data(owner)?;
        self.protocol_owner.ensure_current()?;
        Ok(observer.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_partial_transfer_keeps_every_original_and_spare_bank_counted() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("actual-retained-prepare").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(7),
            method: Method::Begin,
            body: Default::default(),
            extensions: Default::default(),
        };
        let bytes = Vec::with_capacity(773);
        let capacity = bytes.capacity();
        let mut assigned = assigned_restore::AssignedOriginalCompleteRestore {
            original,
            bytes,
            literal_slot: None,
            cut: crate::operational_time::OperationalDeadline::expired_fixture(),
            phase: assigned_restore::Phase::Unsigned,
            response: None,
            mapping: reference,
            mapping_identity: Rc::new(crate::protocol_snapshot::ArchivedProtocolMappingIdentity),
            nonce: [0; 32],
        };

        for phase in [
            assigned_restore::Phase::Unsigned,
            assigned_restore::Phase::Sealing,
            assigned_restore::Phase::Sealed,
            assigned_restore::Phase::Publishing,
            assigned_restore::Phase::Complete,
        ] {
            assigned.phase = phase;
            assert!(assigned.validate_owned_snapshot().is_err());
            let mut observer = MetadataObserver::new();
            observe_assigned(&assigned, &mut observer).unwrap();
            let facts = observer.finish();

            assert!(facts.vector_capacity_bytes >= capacity);
            assert!(facts.string_capacity_bytes >= "actual-retained-prepare".len());
            assert_eq!(assigned.bytes.capacity(), capacity);
            assert!(assigned.response.is_none());
            assert!(assigned.literal_slot.is_none());
        }
    }
}

#[cfg(all(test, unix))]
mod revoked_owner_tests {
    use super::*;
    use crate::client::ClientContent;

    #[test]
    fn revoked_and_fenced_selected_owner_uses_raw_census_and_refuses_foreign_identity() {
        let (mut handshake, session, owner, witness, _peer) =
            ClientSession::restoration_retained_fixture();
        let content = ClientContent::new(1024 * 1024, 16, 4096).unwrap();
        let custody = ClientCustody::new(16, content).unwrap();
        let mut controller = CnpController::new(
            session,
            custody,
            ControllerRoute {
                node: Id::new("raw-census-node").unwrap(),
                execution_owner: Id::new("raw-census-owner").unwrap(),
            },
            Duration::from_secs(30),
        )
        .unwrap();
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("retained-raw-prepare").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(7),
            method: Method::Begin,
            body: Default::default(),
            extensions: Default::default(),
        };
        // This private model slot is deliberately unsigned and grants no action.
        // The real negotiated codec and supervisor remain actual owning roots.
        controller.original_complete_restore_prepare =
            Some(assigned_restore::AssignedOriginalCompleteRestore {
                original,
                bytes: Vec::with_capacity(773),
                literal_slot: None,
                cut: crate::operational_time::OperationalDeadline::expired_fixture(),
                phase: assigned_restore::Phase::Unsigned,
                response: None,
                mapping: reference,
                mapping_identity: Rc::new(
                    crate::protocol_snapshot::ArchivedProtocolMappingIdentity,
                ),
                nonce: [0; 32],
            });
        let before = controller
            .original_restoration_host_metadata_facts_with_retained_supervisor(
                &owner,
                Some(&witness),
            )
            .unwrap();
        assert!(controller.session.authority().ensure_live().is_ok());

        handshake.contain();
        controller.session.fence_restoration_retained_fixture();
        controller.fenced = true;

        assert!(controller.session.authority().ensure_live().is_err());
        assert!(
            controller
                .session
                .authenticate_original_retained_supervisor(&owner)
                .is_err()
        );
        assert!(
            controller
                .session
                .authenticate_original_protocol_supervisor(&witness)
                .is_err()
        );
        assert!(controller.authenticate_native5_source_codec().is_err());
        let after = controller
            .original_restoration_host_metadata_facts_with_retained_supervisor(
                &owner,
                Some(&witness),
            )
            .unwrap();
        assert!(after.vector_capacity_bytes >= before.vector_capacity_bytes);
        let assigned = controller
            .original_complete_restore_prepare
            .as_ref()
            .unwrap();
        assert!(assigned.bytes.capacity() >= 773);
        assert!(matches!(assigned.phase, assigned_restore::Phase::Unsigned));

        let (_foreign_handshake, foreign_session, foreign_owner, foreign_witness, _foreign_peer) =
            ClientSession::restoration_retained_fixture();
        assert!(
            controller
                .original_restoration_host_metadata_facts_with_retained_supervisor(
                    &foreign_owner,
                    Some(&witness),
                )
                .is_err()
        );
        assert!(
            controller
                .original_restoration_host_metadata_facts_with_retained_supervisor(
                    &owner,
                    Some(&foreign_witness),
                )
                .is_err()
        );
        assert!(
            foreign_session
                .authenticate_original_retained_supervisor_data(&owner)
                .is_err()
        );
        assert!(controller.original_complete_restore_prepare.is_some());
        assert!(controller.session.authority().ensure_live().is_err());
    }
}
