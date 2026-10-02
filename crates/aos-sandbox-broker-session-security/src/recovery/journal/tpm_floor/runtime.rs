//! Attaches the physical floor to the actual two fixed Storage journal owners.
//!
//! Required mode retains the sidecar and helper between opaque traffic borrows.
//! A private whole-owner guard keeps raw public reads unavailable during each
//! reconciliation and restores that same fenced floor on unwind. Schema-only validation
//! is private and grants no currentness. There is no reentrant boolean bypass.
//! Legacy mode admits unrelated Storage traffic but cannot adopt a sidecar or
//! any retained execution-output (46/47/48) history. Public method 46 remains
//! closed pending installed physical TPM/use-boundary qualification.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::{JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};

use super::FloorErrorV1;
use super::durable::{
    BrokerAttachmentAttemptV1, BrokerAttachmentPhaseV1, commit_unfloored_broker_v1,
};
use super::format::FloorEndpointV1;
use super::provisioning::{ImageFloorModeV1, ModePinV1, ProvisionPinV1};
use crate::recovery::journal::{
    BrokerSessionJournalKeyKind, ProtectedBrokerSessionJournalV1, StoredProtocolHistoryV1,
    classified_broker_session_key,
};

/// Deliberately false until physical producer and both installed hooks qualify.
const METHOD46_INSTALLED_QUALIFIED: bool = false;

/// Keeps image mode and physical custody private to the actual journal owner.
pub(in crate::recovery::journal) struct BrokerFloorV1 {
    state: FloorStateV1,
}

enum FloorStateV1 {
    NotScoped,
    Unavailable,
    Legacy {
        mode: ModePinV1,
    },
    Required {
        mode: ModePinV1,
        provision: ProvisionPinV1,
        launch_image: crate::production_startup::Pid1LaunchImageV1,
        attached: BrokerAttachmentAttemptV1,
    },
}

impl BrokerFloorV1 {
    pub(in crate::recovery::journal) fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.check_cold_deadline(),
            _ => Ok(()),
        }
    }

    pub(in crate::recovery::journal) fn bind_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.bind_cold_deadline(deadline),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) fn retire_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.retire_cold_deadline(deadline),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) const fn unavailable() -> Self {
        Self {
            state: FloorStateV1::Unavailable,
        }
    }

    #[cfg(test)]
    pub(in crate::recovery::journal) const fn test_not_scoped() -> Self {
        Self {
            state: FloorStateV1::NotScoped,
        }
    }

    pub(in crate::recovery::journal) fn configure(
        directory: &Path,
        protocol: BrokerSessionProtocolV1,
        role: BrokerSessionDurableEndpointV1,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Result<Self, FloorErrorV1> {
        if protocol != BrokerSessionProtocolV1::Storage {
            if launch_image.is_some() {
                return Err(FloorErrorV1::Provisioning);
            }
            // A different protected role cannot bypass the two fixed Storage
            // directories by opening their journal as an unrelated protocol.
            if matches!(
                directory.to_str(),
                Some(
                    "/var/lib/aos/sandboxd/broker-session/storage"
                        | "/var/lib/aos/sandbox-storage/broker-session"
                )
            ) {
                return Err(FloorErrorV1::Provisioning);
            }
            return Ok(Self {
                state: FloorStateV1::NotScoped,
            });
        }
        let endpoint = match role {
            BrokerSessionDurableEndpointV1::Client => FloorEndpointV1::ControllerStorageClient,
            BrokerSessionDurableEndpointV1::Broker => FloorEndpointV1::StorageBroker,
        };
        let fixed = match endpoint {
            FloorEndpointV1::ControllerStorageClient => {
                "/var/lib/aos/sandboxd/broker-session/storage"
            }
            FloorEndpointV1::StorageBroker => "/var/lib/aos/sandbox-storage/broker-session",
        };
        if directory != Path::new(fixed) {
            #[cfg(test)]
            {
                return Ok(Self::test_not_scoped());
            }
            #[cfg(not(test))]
            {
                return Err(FloorErrorV1::Provisioning);
            }
        }
        let mode = ModePinV1::open(endpoint)?;
        match mode.mode() {
            ImageFloorModeV1::LegacyClosed => {
                if launch_image.is_some() {
                    return Err(FloorErrorV1::Provisioning);
                }
                require_no_floor_names(directory)?;
                Ok(Self {
                    state: FloorStateV1::Legacy { mode },
                })
            }
            ImageFloorModeV1::Required => {
                super::backend::confinement::require_owner(endpoint)?;
                Ok(Self {
                    state: FloorStateV1::Required {
                        mode,
                        provision: ProvisionPinV1::open(endpoint)?,
                        launch_image: launch_image.ok_or(FloorErrorV1::Unavailable)?,
                        attached: BrokerAttachmentAttemptV1::fresh(),
                    },
                })
            }
        }
    }

    pub(in crate::recovery::journal) fn requires_existing(&self) -> bool {
        matches!(
            self.state,
            FloorStateV1::Required { .. } | FloorStateV1::Unavailable
        )
    }

    // Only this actual private state owns the resident attempt that must
    // survive unfinished operations. Other dispositions retain legacy Drop.
    pub(in crate::recovery::journal) fn has_resident_required_attempt(&self) -> bool {
        matches!(&self.state, FloorStateV1::Required { .. })
    }

    pub(in crate::recovery::journal) fn revalidate_endpoint_for_reopen(
        &mut self,
        endpoint: &mut crate::recovery::journal::ProtectedEndpointV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => {
                // This borrows disjoint actual owner fields before extraction.
                // A caught unwind fences the original attempt in place.
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)
                    .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
                match endpoint.revalidate() {
                    Ok(()) => operation.finish(Ok(()))
                        .map_err(|_| crate::BrokerSessionSecurityError::Currentness),
                    Err(cause) => {
                        // This public facade error contains static labels only;
                        // the actual cause remains on the resident attempt.
                        let projected = cause.clone();
                        operation.attempt.record_endpoint_failure(cause);
                        let _ = operation.finish::<()>(Err(FloorErrorV1::Unavailable));
                        Err(projected)
                    }
                }
            }
            _ => endpoint.revalidate(),
        }
    }

    pub(in crate::recovery::journal) fn attach(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required {
                mode,
                provision,
                launch_image,
                attached,
            } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Fresh)?;
                // Main writer is already retained. Open sidecar next, then
                // TPM; this call recovers only its exact persisted transaction.
                let result = (|| {
                    mode.revalidate()?;
                    let profile = provision.profile();
                    if owner.endpoint.protected_protocol_and_node().1 != profile.node() {
                        return Err(FloorErrorV1::Provisioning);
                    }
                    let auth = provision.current_auth()?;
                    let salt_name = provision.salt_name();
                    operation.attempt.admit(
                        owner,
                        profile,
                        salt_name,
                        &auth,
                        launch_image,
                    )?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
            _ => self.check(owner),
        }
    }

    pub(in crate::recovery::journal) fn suspend_for_reopen(&mut self) {
        if let FloorStateV1::Required { attached, .. } = &mut self.state {
            // Release TPM/sidecar before replacing the main writer, then acquire
            // main → sidecar → TPM again. Mode/provisioning pins stay retained.
            let old = std::mem::replace(attached, BrokerAttachmentAttemptV1::fresh());
            drop(old);
        }
    }

    pub(in crate::recovery::journal) fn check(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::NotScoped => Ok(()),
            FloorStateV1::Unavailable => Err(FloorErrorV1::Unavailable),
            FloorStateV1::Legacy { mode } => {
                mode.revalidate()?;
                require_no_floor_names(&owner.directory)?;
                require_no_output_history(owner)?;
                mode.revalidate()
            }
            FloorStateV1::Required {
                mode,
                provision,
                attached,
                ..
            } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    mode.revalidate()?;
                    provision.revalidate()?;
                    operation.attempt.check(owner, provision.profile())?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
        }
    }

    pub(in crate::recovery::journal) fn commit(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.check(owner)?;
        let legacy = matches!(&self.state, FloorStateV1::Legacy { .. });

        match &mut self.state {
            FloorStateV1::Required {
                mode,
                provision,
                attached,
                ..
            } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    operation.attempt.commit(owner, provision.profile(), transaction)?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
            FloorStateV1::NotScoped | FloorStateV1::Legacy { .. } => {
                // Prospective legacy history cannot introduce a hidden 46 row.
                if legacy {
                    require_no_output_transaction(transaction)?;
                }
                commit_unfloored_broker_v1(owner, transaction)?;
                self.check(owner)
            }
            FloorStateV1::Unavailable => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) fn require_method(
        &self,
        method: BrokerMethod,
    ) -> Result<(), FloorErrorV1> {
        if method == BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT {
            if !METHOD46_INSTALLED_QUALIFIED
                || !matches!(
                    &self.state,
                    FloorStateV1::Required {
                        attached,
                        ..
                    } if attached.is_ready()
                )
            {
                return Err(FloorErrorV1::Unavailable);
            }
        }
        if matches!(self.state, FloorStateV1::Legacy { .. }) && is_output_method(method) {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    // A failed (or abandoned in-progress) Required owner cannot touch current
    // names, release sidecar/TPM custody or replace its main writer on reopen.
    pub(in crate::recovery::journal) fn require_reopen_allowed(&self) -> Result<(), FloorErrorV1> {
        if matches!(&self.state, FloorStateV1::Required { attached, .. } if attached.is_failed()) {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(in crate::recovery::journal) fn fence_required(&mut self) {
        if let FloorStateV1::Required { attached, .. } = &mut self.state {
            attached.fence();
        }
    }

    pub(in crate::recovery::journal) fn record_native_failure(
        &mut self,
        cause: aos_sandbox::JournalError,
    ) {
        if let FloorStateV1::Required { attached, .. } = &mut self.state {
            attached.record_native_failure(cause);
        }
        // Unrelated/legacy owners retain their original redacted consuming
        // error contract; no missing lower cause is synthesized for them.
    }
}

fn is_output_method(method: BrokerMethod) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
    )
}

pub(in crate::recovery::journal) fn require_launch_image_presence(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    supplied: bool,
) -> Result<(), FloorErrorV1> {
    let endpoint = match endpoint {
        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient => {
            FloorEndpointV1::ControllerStorageClient
        }
        crate::ProtectedBrokerSessionFixedEndpointV1::StorageBroker => {
            FloorEndpointV1::StorageBroker
        }
        _ => return Err(FloorErrorV1::Provisioning),
    };
    let mode = ModePinV1::open(endpoint)?;
    require_mode_image_presence(mode.mode(), supplied)?;
    if mode.mode() == ImageFloorModeV1::Required {
        super::backend::confinement::require_owner(endpoint)?;
    }
    mode.revalidate()
}

fn require_mode_image_presence(mode: ImageFloorModeV1, supplied: bool) -> Result<(), FloorErrorV1> {
    if supplied != matches!(mode, ImageFloorModeV1::Required) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn require_no_floor_names(directory: &Path) -> Result<(), FloorErrorV1> {
    for name in [
        "session-floor.journal",
        "session-floor.journal.lock",
        "session-floor.journal.compact.tmp",
    ] {
        match std::fs::symlink_metadata(directory.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(FloorErrorV1::Provisioning),
        }
    }
    Ok(())
}

fn require_no_output_history(
    owner: &mut ProtectedBrokerSessionJournalV1,
) -> Result<(), FloorErrorV1> {
    let authority = owner
        .journal_mut()
        .map_err(|_| FloorErrorV1::Unavailable)?
        .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
        .map_err(|_| FloorErrorV1::Unavailable)?;
    for (key, value) in authority.records().map_err(|_| FloorErrorV1::Unavailable)? {
        require_no_output_record(key, value)?;
    }
    Ok(())
}

fn require_no_output_transaction(transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::BrokerSessionTraffic {
            return Err(FloorErrorV1::Encoding);
        }
        if let Some(value) = record.value() {
            require_no_output_record(record.key(), value)?;
        }
    }
    Ok(())
}

fn require_no_output_record(key: &[u8], value: &[u8]) -> Result<(), FloorErrorV1> {
    let kind = classified_broker_session_key(key)
        .map_err(|_| FloorErrorV1::Encoding)?
        .0;
    if kind == BrokerSessionJournalKeyKind::Traffic {
        let history =
            StoredProtocolHistoryV1::decode(key, value).map_err(|_| FloorErrorV1::Encoding)?;
        if history
            .history_model()
            .map_err(|_| FloorErrorV1::Encoding)?
            .records()
            .iter()
            .any(|record| is_output_method(record.method()))
        {
            return Err(FloorErrorV1::Diverged);
        }
    }
    // Other typed archives are separately schema-checked before owner use;
    // their strict formats retain only snapshot/inventory/Host37/39 methods.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_dispositions_do_not_select_required_unwind_restoration() {
        assert!(!BrokerFloorV1::test_not_scoped().has_resident_required_attempt());
        assert!(!BrokerFloorV1::unavailable().has_resident_required_attempt());
    }

    #[test]
    fn tpm_floor_method46_is_closed_without_installed_qualification() {
        for gate in [
            BrokerFloorV1::test_not_scoped(),
            BrokerFloorV1::unavailable(),
        ] {
            assert!(
                gate.require_method(BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT)
                    .is_err()
            );
        }
        assert!(
            BrokerFloorV1::test_not_scoped()
                .require_method(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
                .is_ok()
        );
    }

    #[test]
    fn tpm_floor_fixed_storage_root_cannot_be_reclassified_as_host() {
        for directory in [
            "/var/lib/aos/sandboxd/broker-session/storage",
            "/var/lib/aos/sandbox-storage/broker-session",
        ] {
            assert!(
                BrokerFloorV1::configure(
                    Path::new(directory),
                    BrokerSessionProtocolV1::Host,
                    BrokerSessionDurableEndpointV1::Client,
                    None,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn tpm_floor_legacy_rejects_any_sidecar_name_without_deleting_it() {
        let directory = tempfile::tempdir().unwrap();
        assert!(require_no_floor_names(directory.path()).is_ok());
        for name in [
            "session-floor.journal",
            "session-floor.journal.lock",
            "session-floor.journal.compact.tmp",
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, b"retained").unwrap();
            assert!(require_no_floor_names(directory.path()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"retained");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn tpm_floor_startup_image_presence_cannot_downgrade_required_mode() {
        assert!(require_mode_image_presence(ImageFloorModeV1::LegacyClosed, false).is_ok());
        assert!(require_mode_image_presence(ImageFloorModeV1::Required, true).is_ok());
        assert!(require_mode_image_presence(ImageFloorModeV1::Required, false).is_err());
        assert!(require_mode_image_presence(ImageFloorModeV1::LegacyClosed, true).is_err());
    }
}
