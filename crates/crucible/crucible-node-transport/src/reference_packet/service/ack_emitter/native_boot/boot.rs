//! Authenticates one inherited private boot and its actual assigned Admit.

use crate::reference_packet::service::{PacketNative5SourceLaunch, ack_emitter::*};
use crate::{
    ProviderError, envelope::Envelope, handshake::ConnectionAuthority,
    native_hello::OriginalNativeHelloJournal,
};
use crucible_node_format::{Bytes, ContentRef, ContractError, Id, U64, canonical};
use serde::Deserialize;
use std::{cell::RefCell, mem::size_of, rc::Rc, thread::ThreadId};

#[path = "boot_shape.rs"]
mod shape;

#[path = "owned11.rs"]
mod owned11;

#[path = "boot_settled_current.rs"]
mod settled_current;

#[path = "restore.rs"]
mod restore;
pub(crate) use restore::{
    NativeRestorationActivationAttempt, NativeRestorationObservationAttempt,
    NativeRestorationUploadAttempt, OriginalRestorationActivationPermit,
    OriginalRestorationActivationRequirement, OriginalRestorationObservationPermit,
    OriginalRestorationObservationRead, OriginalRestorationReleaseState,
    OriginalRestorationReleased, OriginalRestorationUploadPermit,
    OriginalRestoredSuffixPostObservation,
    original_native_restoration_activation_attempt_backing_data,
    original_native_restoration_activation_counter_scratch_data,
    original_native_restoration_activation_ingress_row_data,
    original_native_restoration_activation_ingress_storage_data,
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
    original_native_restoration_observation_ingress_row_data,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
    original_restored_suffix_post_observation_counter_scratch_data,
};
pub(crate) use restore::{
    NativeRestoredControlEvidence, OriginalCompleteRestoreCommit, VerifiedCompleteRestoration,
    VerifiedCompleteRestorationHeld,
};
pub use restore::{
    PacketNativeRestoreCommitConstructionData, PacketNativeRestoreCommitConstructionInputs,
    original_native_restore_commit_construction_counter_scratch_data,
    original_native_restore_commit_construction_storage_data,
};
#[path = "restore_prepare.rs"]
mod restore_prepare;
pub(crate) use restore_prepare::{
    VerifiedCanonicalRestoreInputAdmission, VerifiedCompleteRestorePrepare,
};

#[path = "report_startup.rs"]
mod report_startup;
pub(crate) use report_startup::{
    OriginalNativeReportStartupAllocation, original_native_report_startup_scope_layout_data,
};

#[path = "boot_invocation.rs"]
mod invocation;
#[path = "native_startup.rs"]
pub(super) mod native_startup;
pub(crate) use native_startup::OriginalNativeBirthReadScope;

// Keep the prospective baseline producer tied to the exact constructor banks.
pub(crate) const ORIGINAL_ACK_CONTEXT_BANK_BYTES: [usize; 5] =
    [512 * 1024, 4 * 1024, 416 * 1024, 16 * 1024, 65_536];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootData {
    schema: String,
    private_key: Bytes,
    birth_id: Bytes,
    source_birth: serde_json::Value,
    expected_host_registration: serde_json::Value,
    private_launch: Id,
    host_executable: ContentRef,
}

// Retains the original decoded children before the independent native row
// permits construction of the larger Rc-owned boot. Bootstrap owns this inline.
pub(super) struct OriginalNativeStartupBootAttempt {
    launch_body: Vec<u8>,
    data: Option<BootData>,
}

// Pays the actual attempt/helper loans before the independent native-row claim.
pub(in crate::reference_packet::service) fn original_native_startup_attempt_counter_scratch_data()
-> usize {
    2 * size_of::<&serde_json::Value>()
        + 2 * size_of::<&PacketNative5SourceLaunch>()
        + 2 * size_of::<&mut super::bootstrap::admitted::OriginalNativeStartupBootstrap>()
        + size_of::<&mut Option<OriginalNativeStartupBootAttempt>>()
        + 2 * size_of::<&mut OriginalNativeStartupBootAttempt>()
        + 2 * size_of::<&mut Option<Rc<RefCell<NativeAckBoot>>>>()
        + size_of::<&BootData>()
        + size_of::<Option<&BootData>>()
        + size_of::<Result<&BootData, ProviderError>>()
        + 2 * size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<bool>()
        + 2 * size_of::<usize>()
        + shape::counter_scratch_data()
        + invocation::attempt_counter_scratch_data()
}

// Counts the owned initializer and Option assignment separately from the
// resident inline slot already included in Bootstrap's retained layout.
pub(in crate::reference_packet::service) const fn original_native_startup_attempt_transient_data()
-> usize {
    size_of::<OriginalNativeStartupBootAttempt>()
        + size_of::<Option<OriginalNativeStartupBootAttempt>>()
        + size_of::<Result<BootData, ContractError>>()
        + size_of::<Option<BootData>>()
        + size_of::<Result<BootData, ProviderError>>()
        + shape::construction_transient_data()
}

pub(crate) struct NativeAckBoot {
    // Only the separate resource-admitted bootstrap constructor may create
    // Some. The existing boot5 constructor remains explicitly unavailable to it.
    creator: u32,
    thread: ThreadId,
    data: BootData,
    launch_body: Vec<u8>,
    pub(crate) policy: Option<Rc<crate::reference_packet::Native5Policy>>,
    source_body: Vec<u8>,
    host_body: Vec<u8>,
    normalized: [Option<serde_json::Value>; 5],
    banks: [Vec<u8>; 5],
    context: Option<PacketCanonicalAckAdmissionContext>,
    proof: Option<PacketCanonicalAckAdmissionProof>,
    original: Option<Envelope>,
    ready: bool,
    attempted: bool,
    verified: bool,
    restoration: Option<Rc<RefCell<restore::NativeCompleteRestoreAttempt>>>,
    transfer: Option<Rc<RefCell<restore_prepare::NativeCompleteRestorePrepareAttempt>>>,
    startup: Option<native_startup::OriginalNativeStartupBoot>,
    restoration_activation: [Option<Rc<RefCell<NativeRestorationActivationAttempt>>>; 2],
    restoration_uploads: [Option<Rc<RefCell<NativeRestorationUploadAttempt>>>; 2],
    restoration_observation: Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
    restored_settled: Option<super::restored_settled::NativeRestoredSettledCaptureOwner>,
}

/// Returns the actual shared boot payload layout for historical row validation.
pub(crate) const fn original_native_ack_boot_layout() -> usize {
    std::mem::size_of::<RefCell<NativeAckBoot>>()
}

pub(crate) struct VerifiedCanonicalAckAdmission {
    identity: crate::connection::OriginalNativeAckConnectionIdentity,
    pub(crate) boot: Rc<RefCell<NativeAckBoot>>,
    pub(crate) policy: Rc<crate::reference_packet::Native5Policy>,
    pub(crate) authority: ConnectionAuthority,
    pub(crate) original: Envelope,
}

impl NativeAckBoot {
    pub(super) fn prepare_into(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        original_launch_body: Vec<u8>,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(ProviderError::Conflict("native ACK boot already attempted"));
        }
        crate::connection::serialized_credit(value, 512 * 1024)?;
        let data: BootData =
            BootData::deserialize(value).map_err(crucible_node_format::ContractError::from)?;
        Self::prepare_data_into(data, launch, original_launch_body, None, None, completed)
    }

    // Only the actual selected inherited bootstrap owns the nonrenewing claim.
    // The ordinary boot5 entry cannot supply it or accept the new class.
    pub(super) fn prepare_original_startup_into(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        original_launch_body: Vec<u8>,
        startup: &mut super::bootstrap::admitted::OriginalNativeStartupBootstrap,
        attempt: &mut Option<OriginalNativeStartupBootAttempt>,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() || attempt.is_some() {
            return Err(ProviderError::Conflict("native ACK boot already attempted"));
        }
        let retained = attempt.insert(OriginalNativeStartupBootAttempt {
            launch_body: original_launch_body,
            data: None,
        });
        let result = Self::prepare_original_startup_attempt_data(
            value, launch, startup, retained, completed,
        );
        // Installation moves every decoded child and the launch copy into the
        // native boot, including when its later preparation fails. Only the
        // emptied inline slot is released; pre-claim refusals keep their inputs.
        if completed.is_some() {
            *attempt = None;
        }
        if result.is_err() {
            startup.failed = true;
        }
        result
    }

    fn prepare_original_startup_attempt_data(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        startup: &mut super::bootstrap::admitted::OriginalNativeStartupBootstrap,
        attempt: &mut OriginalNativeStartupBootAttempt,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        startup.ensure_original()?;
        crate::connection::serialized_credit(value, startup.maximum_boot_bytes)?;
        // Check every fallible DTO spelling while all inputs remain borrowed.
        // The subsequent copies cannot reject a later field after dropping an
        // earlier decoded child. This inspection grants no native row claim.
        let shape = shape::inspect_data(value)?;
        attempt.data = Some(shape.copy_data()?);
        let data = attempt.data.as_ref().ok_or(ProviderError::Correlation(
            "native startup decoded boot absent",
        ))?;
        let admitted = startup.claim_birth_data(
            launch,
            &attempt.launch_body,
            &data.source_birth,
            &data.expected_host_registration,
            &data.private_launch,
            data.private_key.as_slice(),
            data.birth_id.as_slice(),
        )?;
        let data = attempt.data.take().ok_or(ProviderError::Correlation(
            "native startup decoded boot transferred",
        ))?;
        Self::prepare_data_into(
            data,
            launch,
            std::mem::take(&mut attempt.launch_body),
            Some(admitted),
            None,
            completed,
        )
    }

    fn prepare_data_into(
        data: BootData,
        launch: &PacketNative5SourceLaunch,
        original_launch_body: Vec<u8>,
        startup: Option<native_startup::OriginalNativeStartupBoot>,
        invocation: Option<
            crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData,
        >,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        let original = Self::retain_boot_data_into(data, original_launch_body, startup, completed);
        Self::prepare_retained_data(&original, launch, invocation)
    }

    // Installs the native owner before subsequent policy/model preparation.
    fn retain_boot_data_into(
        data: BootData,
        original_launch_body: Vec<u8>,
        startup: Option<native_startup::OriginalNativeStartupBoot>,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Rc<RefCell<Self>> {
        let original = Rc::new(RefCell::new(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            data,
            launch_body: original_launch_body,
            policy: None,
            source_body: Vec::new(),
            host_body: Vec::new(),
            normalized: std::array::from_fn(|_| None),
            banks: std::array::from_fn(|_| Vec::new()),
            context: None,
            proof: None,
            original: None,
            ready: false,
            attempted: false,
            verified: false,
            restoration: None,
            restoration_activation: std::array::from_fn(|_| None),
            restoration_uploads: std::array::from_fn(|_| None),
            restoration_observation: None,
            restored_settled: None,
            transfer: None,
            startup,
        }));
        *completed = Some(Rc::clone(&original));
        original
    }

    fn prepare_retained_data(
        original: &Rc<RefCell<Self>>,
        launch: &PacketNative5SourceLaunch,
        invocation: Option<
            crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData,
        >,
    ) -> Result<(), ProviderError> {
        let mut owner = original
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
        owner.ensure_origin()?;
        let startup_selected = owner.startup.is_some();
        let boot_schema = if invocation.is_some() {
            crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA
        } else if startup_selected {
            crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA
        } else {
            "source-owned.packet-canonical-ack-private-boot/5"
        };
        if owner.data.schema != boot_schema
            || owner.data.private_key.as_slice().len() != 32
            || owner.data.birth_id.as_slice().len() != 32
            || owner.data.host_executable != launch.controller_executable
        {
            return Err(ProviderError::Correlation(
                "native private ACK boot grammar",
            ));
        }
        let expected = blake3::Hash::from(blake3::derive_key(
            "source-owned.packet-canonical-ack-birth/5",
            owner.data.private_key.as_slice(),
        ));
        if expected != *owner.data.birth_id.as_slice() {
            return Err(ProviderError::Correlation(
                "native private ACK birth identity",
            ));
        }
        let source = &owner.data.source_birth;
        let object = source
            .as_object()
            .ok_or(ProviderError::Correlation("native source binding object"))?;
        let mut keys = vec![
            "schema",
            "selection",
            "program",
            "coordinator",
            "limits",
            "storage",
            "capture_profile",
            "confirmation_selection",
            "ack_emitter_selection",
            "codec_metadata_extent",
        ];
        let report_selected = launch.capture_allocation_selection.is_some()
            || launch.fresh_restore_allocation_selection.is_some();
        let schema = if startup_selected {
            keys.extend([
                "native_codec_metadata_extent", "protocol_metadata_limits",
                "complete_restore_selection", "restore_input_emitter_selection",
                "capture_allocation_selection", "fresh_restore_allocation_selection",
                "report_startup_allocation", "native_startup_allocation",
            ]);
            if invocation.is_some() {
                keys.push("invocation");
                crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA
            } else {
                crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA
            }
        } else if report_selected {
            keys.extend([
                "native_codec_metadata_extent", "protocol_metadata_limits",
                "complete_restore_selection", "restore_input_emitter_selection",
                "capture_allocation_selection", "fresh_restore_allocation_selection",
                "report_startup_allocation",
            ]);
            "source-owned.packet-canonical-ack-source-binding/13"
        } else if launch.restore_input_emitter_selection.is_some() {
            keys.extend(["native_codec_metadata_extent", "protocol_metadata_limits", "complete_restore_selection", "restore_input_emitter_selection"]);
            "source-owned.packet-canonical-ack-source-binding/11"
        } else if launch.complete_restore_selection == Some(
            crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            keys.push("complete_restore_selection");
            "source-owned.packet-canonical-ack-source-binding/10"
        } else if launch.complete_restore_selection.is_some() {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            keys.push("complete_restore_selection");
            "source-owned.packet-canonical-ack-source-binding/9"
        } else if launch.protocol_metadata_limits.is_some() {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            "source-owned.packet-canonical-ack-source-binding/8"
        } else if launch.native_codec_metadata_extent.is_some() {
            keys.push("native_codec_metadata_extent");
            "source-owned.packet-canonical-ack-source-binding/7"
        } else {
            "source-owned.packet-canonical-ack-source-binding/6"
        };
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || source["schema"] != schema
            || source["codec_metadata_extent"] != "CanonicalAck512KiB"
        {
            return Err(ProviderError::Correlation("native source binding grammar"));
        }
        let coordinator = canonical::parse_json(
            launch.initial_coordinator.bytes.as_slice(),
            crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
        )?;
        let mut expected_source = serde_json::json!({"schema":schema, "selection":launch.selection,"program":launch.program,"coordinator":coordinator,"limits":launch.limits,"storage":launch.storage,"capture_profile":launch.capture_profile,"confirmation_selection":launch.confirmation_selection,"ack_emitter_selection":launch.ack_emitter_selection,"codec_metadata_extent":"CanonicalAck512KiB"});
        if let Some(extent) = launch.native_codec_metadata_extent {
            expected_source["native_codec_metadata_extent"] =
                serde_json::to_value(extent).map_err(ContractError::from)?;
        }
        if let Some(metadata) = launch.protocol_metadata_limits {
            expected_source["protocol_metadata_limits"] =
                serde_json::to_value(metadata).map_err(ContractError::from)?;
        }
        if let Some(restoration) = launch.complete_restore_selection {
            expected_source["complete_restore_selection"] =
                serde_json::to_value(restoration).map_err(ContractError::from)?;
        }
        if let Some(emitter) = launch.restore_input_emitter_selection {
            expected_source["restore_input_emitter_selection"] =
                serde_json::to_value(emitter).map_err(ContractError::from)?;
        }
        if let Some(selection) = launch.capture_allocation_selection {
            expected_source["capture_allocation_selection"] =
                serde_json::to_value(selection).map_err(ContractError::from)?;
            expected_source["complete_restore_selection"] =
                serde_json::to_value(launch.complete_restore_selection)
                    .map_err(ContractError::from)?;
            expected_source["restore_input_emitter_selection"] =
                serde_json::to_value(launch.restore_input_emitter_selection)
                    .map_err(ContractError::from)?;
        }
        if report_selected {
            if let Some(purpose) = invocation.as_ref() {
                // Only the already claimed private invocation reaches this
                // branch. Check the complete target and same Source purpose
                // before selecting its reachable report constructor.
                purpose.authenticate_target_data(launch)?;
                if crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::from_original_value_data(
                    source.get("invocation").ok_or(ProviderError::Correlation("native invocation Source purpose"))?,
                )? != *purpose {
                    return Err(ProviderError::Correlation("native invocation Source purpose differs"));
                }
                report_startup::authenticate_invocation_binding_data(
                    &source["report_startup_allocation"],
                    launch,
                    purpose,
                )?;
            } else {
                report_startup::authenticate_binding_data(
                    &source["report_startup_allocation"],
                    launch.capture_allocation_selection,
                    launch.fresh_restore_allocation_selection,
                )?;
            }
            expected_source["capture_allocation_selection"] =
                serde_json::to_value(launch.capture_allocation_selection)
                    .map_err(ContractError::from)?;
            expected_source["fresh_restore_allocation_selection"] =
                serde_json::to_value(launch.fresh_restore_allocation_selection)
                    .map_err(ContractError::from)?;
            expected_source["complete_restore_selection"] =
                serde_json::to_value(launch.complete_restore_selection)
                    .map_err(ContractError::from)?;
            expected_source["restore_input_emitter_selection"] =
                serde_json::to_value(launch.restore_input_emitter_selection)
                    .map_err(ContractError::from)?;
            // The private Source finalizer is the only cross-process issuer.
            // Validate the closed data and purpose association before retaining
            // its exact object; no portable row alone can construct a token.
            expected_source["report_startup_allocation"] =
                source["report_startup_allocation"].clone();
        }
        if startup_selected {
            for (name, value) in [
                (
                    "native_codec_metadata_extent",
                    serde_json::to_value(launch.native_codec_metadata_extent),
                ),
                (
                    "protocol_metadata_limits",
                    serde_json::to_value(launch.protocol_metadata_limits),
                ),
                (
                    "complete_restore_selection",
                    serde_json::to_value(launch.complete_restore_selection),
                ),
                (
                    "restore_input_emitter_selection",
                    serde_json::to_value(launch.restore_input_emitter_selection),
                ),
                (
                    "capture_allocation_selection",
                    serde_json::to_value(launch.capture_allocation_selection),
                ),
                (
                    "fresh_restore_allocation_selection",
                    serde_json::to_value(launch.fresh_restore_allocation_selection),
                ),
            ] {
                expected_source[name] = value.map_err(ContractError::from)?;
            }
            if !report_selected {
                expected_source["report_startup_allocation"] = serde_json::Value::Null;
            }
            // The actual private scope already compared the complete closed
            // object with its fixed MAC-bound rows before model construction.
            expected_source["native_startup_allocation"] =
                source["native_startup_allocation"].clone();
        }
        if let Some(purpose) = invocation {
            purpose.authenticate_target_data(launch)?;
            if crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::from_original_value_data(
                source.get("invocation").ok_or(ProviderError::Correlation("native invocation Source purpose"))?,
            )? != purpose {
                return Err(ProviderError::Correlation("native invocation Source purpose differs"));
            }
            expected_source["invocation"] =
                serde_json::to_value(purpose).map_err(ContractError::from)?;
        }
        if *source != expected_source {
            return Err(ProviderError::Correlation(
                "native original source binding differs",
            ));
        }
        owner.source_body = canonical::canonical_json(&owner.data.source_birth)?;
        owner.host_body = canonical::canonical_json(&owner.data.expected_host_registration)?;
        if owner.source_body.len() > 384 * 1024 || owner.host_body.len() > 16 * 1024 {
            return Err(ProviderError::ResourceExhausted(
                "native ACK boot input extent",
            ));
        }
        for (bank, limit) in owner.banks.iter_mut().zip(ORIGINAL_ACK_CONTEXT_BANK_BYTES) {
            bank.try_reserve_exact(limit)
                .map_err(|_| ProviderError::ResourceExhausted("native ACK context bank"))?;
        }
        owner.ready = true;
        Ok(())
    }

    pub(crate) fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation("native ACK boot foreign origin"));
        }
        Ok(())
    }
}

impl NativeAckBoot {
    pub(crate) fn verify_admit<S: crate::connection::ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        policy: Rc<crate::reference_packet::Native5Policy>,
        authority: &ConnectionAuthority,
        hello: &OriginalNativeHelloJournal,
        original: &Envelope,
        connection: &crate::connection::Connection<S>,
    ) -> Result<VerifiedCanonicalAckAdmission, ProviderError> {
        connection.authenticate_native5_source_codec()?;
        authority.ensure_live()?;
        let mut owner = boot
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
        owner.ensure_origin()?;
        if !owner.ready || owner.attempted {
            return Err(ProviderError::Conflict(
                "native ACK Admit already attempted",
            ));
        }
        owner.attempted = true;
        let launch = owner.decode_original_launch_data()?;
        owner.original = Some(original.clone());
        let proof_value = original
            .extensions
            .get(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
            .ok_or(ProviderError::Correlation("native assigned proof absent"))?;
        validate_proof_value(proof_value)?;
        owner.proof = Some(
            serde_json::from_value(proof_value.clone())
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let expected_host = &owner.data.expected_host_registration;
        let host = expected_host.as_object().ok_or(ProviderError::Correlation(
            "native host registration grammar",
        ))?;
        let keys = [
            "schema",
            "role",
            "connection_id",
            "session_id",
            "incarnation_id",
            "limits",
            "features",
            "extensions",
            "envelope_extensions",
        ];
        if host.len() != keys.len() || keys.iter().any(|key| !host.contains_key(*key)) {
            return Err(ProviderError::Correlation(
                "native host registration closed grammar",
            ));
        }
        let host_connection_id: Id = serde_json::from_value(host["connection_id"].clone())
            .map_err(crucible_node_format::ContractError::from)?;
        let extensions = authority
            .selected_extensions()
            .ok_or(ProviderError::Correlation(
                "native typed extension roster absent",
            ))?;
        let registration = |role: &str, id: &Id| serde_json::json!({"schema":"source-owned.packet-canonical-ack-registration/5","role":role,"connection_id":id,"session_id":authority.session_id(),"incarnation_id":authority.incarnation_id(),"limits":authority.limits(),"features":authority.selected_features(),"extensions":extensions,"envelope_extensions":authority.envelope_extensions()});
        if registration("controller", &host_connection_id) != *expected_host {
            return Err(ProviderError::Correlation(
                "native negotiated host registration differs",
            ));
        }
        let expected_body = serde_json::to_value(crate::bodies::AdmitRequest {
            bindings: launch.selection.realization.bindings.clone(),
            world_binding_hash: launch.selection.world.clone(),
            admission_receipt: launch.selection.admission_receipt.clone(),
            extensions: Default::default(),
        })
        .map_err(crucible_node_format::ContractError::from)?;
        if original.method != crate::envelope::Method::Admit
            || original.message != crate::envelope::MessageKind::Request
            || original.extensions.len() != 1
            || serde_json::Value::Object(original.body.clone()) != expected_body
        {
            return Err(ProviderError::Correlation(
                "native assigned Admit body differs",
            ));
        }
        let native_executable = if owner.startup.is_some() {
            measure_original_prepare_executable_data(std::path::Path::new("/proc/self/exe"))?
        } else {
            crate::conformance::measure_executable(&std::env::current_exe()?)?
        };
        owner.normalized[0] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-birth-association/5","birth_id":owner.data.birth_id,"private_launch":owner.data.private_launch,"host_executable":owner.data.host_executable,"source_binding":owner.data.source_birth,"expected_host_registration":owner.data.expected_host_registration}),
        );
        owner.normalized[1] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-kernel-binding/5","controller":{"pid":launch.controller_pid,"uid":launch.controller_uid,"executable":launch.controller_executable},"native":{"pid":U64::new(u64::from(std::process::id())),"uid":U64::new(u64::from(rustix::process::geteuid().as_raw())),"executable":native_executable}}),
        );
        owner.normalized[2] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-policy-binding/5","source_binding":owner.data.source_birth,"negotiated":{"limits":authority.limits(),"features":authority.selected_features(),"extensions":extensions,"envelope_extensions":authority.envelope_extensions()}}),
        );
        owner.normalized[3] = Some(registration("native", authority.connection_id()));
        let mut base = original.clone();
        base.extensions
            .remove(PACKET_CANONICAL_ACK_ADMISSION_FEATURE);
        owner.normalized[4] =
            Some(serde_json::to_value(base).map_err(crucible_node_format::ContractError::from)?);
        for index in 0..5 {
            let value = owner.normalized[index]
                .as_ref()
                .ok_or(ProviderError::Correlation("native context value absent"))?;
            let bytes = canonical::canonical_json(value)?;
            if bytes.len() > owner.banks[index].capacity() {
                return Err(ProviderError::ResourceExhausted(
                    "native context selected extent",
                ));
            }
            owner.banks[index].extend_from_slice(&bytes);
        }
        let pair = hello.original_literal_frame_digests()?;
        let digest = |b: &[u8]| Bytes::new(blake3::hash(b).as_bytes().to_vec());
        owner.context = Some(PacketCanonicalAckAdmissionContext {
            schema: "source-owned.packet-canonical-ack-admission-context/5".into(),
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.into(),
            source_birth: digest(&owner.banks[0]),
            kernel_binding: digest(&owner.banks[1]),
            policy_binding: digest(&owner.banks[2]),
            host_registration: digest(&owner.host_body),
            native_registration: digest(&owner.banks[3]),
            hello_request: Bytes::new(pair.request_frame_digest.to_vec()),
            hello_response: Bytes::new(pair.response_frame_digest.to_vec()),
            assigned_admit: digest(&owner.banks[4]),
        });
        let key: [u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Correlation("native retained key extent"))?;
        verify_canonical_ack_admission_proof_data(
            &key,
            owner
                .context
                .as_ref()
                .ok_or(ProviderError::Correlation("native context absent"))?,
            owner
                .proof
                .as_ref()
                .ok_or(ProviderError::Correlation("native proof absent"))?,
        )?;
        owner.ensure_origin()?;
        authority.ensure_live()?;
        let identity = connection.retain_original_native_ack_identity(original, &policy)?;
        identity.authenticate_installation(connection, original)?;
        owner.verified = true;
        Ok(VerifiedCanonicalAckAdmission {
            identity,
            boot: Rc::clone(boot),
            policy,
            authority: authority.clone(),
            original: original.clone(),
        })
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn authenticate_installation<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_native5_source_codec()?;
        self.authenticate_retained_issuer()?;
        self.identity
            .authenticate_installation(connection, &self.original)
    }

    pub(crate) fn authenticate_current<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_native5_source_codec()?;
        self.authenticate_retained_issuer()?;
        self.identity.authenticate_current(connection)
    }

    fn authenticate_retained_issuer(&self) -> Result<(), ProviderError> {
        self.authority.ensure_live()?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native verified boot borrowed"))?;
        boot.ensure_origin()?;
        if !boot.verified
            || boot.original.as_ref() != Some(&self.original)
            || !boot
                .policy
                .as_ref()
                .is_some_and(|policy| Rc::ptr_eq(policy, &self.policy))
        {
            return Err(ProviderError::Correlation(
                "native verified original issuer differs",
            ));
        }
        Ok(())
    }
}

#[path = "control_admit.rs"]
mod control_admit;
pub(crate) use control_admit::OriginalCanonicalAckControlAdmit;

pub(crate) use restore_prepare::{
    OriginalNativePrepareStartupAllocation, measure_conformance_executable_data,
    measure_original_prepare_executable_data,
    original_conformance_executable_measurement_counter_scratch_data,
    original_prepare_executable_measurement_construction_data,
    original_prepare_executable_measurement_counter_scratch_data,
    original_prepare_executable_reference_retained_backing_data,
};
pub use restore_prepare::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};
pub(in crate::reference_packet::service::ack_emitter::native_boot) use restore_prepare::{
    measure_original_restore_controller_executable, measure_original_restore_current_executable,
};

#[path = "restored_suffix.rs"]
pub(super) mod restored_suffix;
pub(crate) use restored_suffix::{
    OriginalRestoredProducerRead, OriginalRestoredSuffixObserveRead,
    original_restored_suffix_native_counter_scratch_data,
    original_restored_suffix_native_header_data,
};

pub(crate) use restore::{HistoricalCommitToken17, HistoricalHeldToken17};

pub(crate) use report_startup::HistoricalReportStartupAllocation17;
pub(crate) use restore_prepare::HistoricalPrepareStartupAllocation17;

#[path = "boot/settled_token.rs"]
mod settled_token_history;

#[path = "boot/observation17.rs"]
mod observation17;
pub(crate) use observation17::{
    NativeObservation17SpentAction, OriginalNativeObservation17Read,
    native_observation17_scope_counter_scratch_data,
};

pub(crate) use restore::{
    NativeObservation17OwningCheckpointData,
    original_observation17_checkpoint_owner_counter_scratch_data,
};

#[path = "boot/capture17.rs"]
mod capture17;
pub(crate) use capture17::{
    NativeCapture17UploadSpentAction, OriginalNativeCapture17Read,
    native_capture17_receive_scope_counter_scratch_data,
    native_capture17_upload_scope_counter_scratch_data,
};

#[cfg(test)]
#[path = "boot_startup_tests.rs"]
mod startup_tests;
