//! Retains the actual fixed floor configuration before initial native reads.
//!
//! Existing ordinary and selected callers share one ordered recipe. This owner
//! parks partial mode, confinement, provisioning and absence observations; only
//! genuine enclosing startup receivers pay its fixed and later journal stages.

use super::*;
use super::super::backend::confinement::OwnerConfinementOriginalV1;
use super::super::provisioning::{
    AbsentFloorNamesOriginalV1, CredentialReadCustodyV1, InitialModeOriginalV1,
    InitialProvisionOriginalV1,
};

pub(in crate::recovery::journal) struct InitialFloorConfigurationOriginalV1 {
    mode_original: InitialModeOriginalV1,
    mode: Option<ModePinV1>,
    absence: AbsentFloorNamesOriginalV1,
    confinement: OwnerConfinementOriginalV1,
    provision_original: InitialProvisionOriginalV1,
    provision: Option<ProvisionPinV1>,
    floor: Option<BrokerFloorV1>,
    launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    taken: bool,
}

impl InitialFloorConfigurationOriginalV1 {
    pub(in crate::recovery::journal) fn new() -> Self {
        Self {
            mode_original: InitialModeOriginalV1::new(),
            mode: None,
            absence: AbsentFloorNamesOriginalV1::new(),
            confinement: OwnerConfinementOriginalV1::new(),
            provision_original: InitialProvisionOriginalV1::new(),
            provision: None,
            floor: None,
            launch_image: None,
            result: None,
            entered: false,
            taken: false,
        }
    }

    /// Describes this exact fixed initial owner before any path or native work.
    pub(in crate::recovery::journal) fn fixed_shape_v1(
        role: aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1,
    ) -> Option<aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1> {
        let storage = role == aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage;
        let work_bytes = if storage {
            // Mode canonicalization and its final comparison run sequentially;
            // the first original target remains held across the second peak.
            super::super::provisioning::auxiliary_currentness_work_bytes_v1()?
                .checked_add(4096_usize.checked_mul(4)?)?
                .checked_add(8 * 1024)?
        } else {
            // The other existing protocols select NotScoped before mode IO.
            0
        };
        // Box::new(Self::new()) may overlap its construction temporary with
        // the boxed destination. Count both actual same-type representations;
        // neither optimizer elision nor the fixed byte-work lane funds it.
        let heap_bytes = std::mem::size_of::<Self>().checked_add(work_bytes)?;
        Some(aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: std::mem::size_of::<Self>(),
            heap_bytes,
            // Three mode files (held +initial byte read +final byte read),
            // two provisioning credentials and two owner-confinement reads.
            open_files: if storage { 7 } else { 0 },
            metadata_cells: if storage {
                // Same initial mode41 +provision25 +three absent-name
                // results/bindings+whole7 +two confinement readers and their
                // two bindings/whole13 +this whole configuration result1.
                let cells = super::super::provisioning::INITIAL_MODE_RESULT_CELLS_V1
                    .checked_add(super::super::provisioning::INITIAL_PROVISION_RESULT_CELLS_V1)?
                    .checked_add(7)?
                    .checked_add(13)?
                    .checked_add(1)?
                    // The fresh Required attempt now also owns its distinct
                    // Controller fixed Result and boxed opening destination.
                    .checked_add(2)?;
                usize::try_from(cells).ok()?
            } else {
                1
            },
        })
    }

    pub(in crate::recovery::journal) fn configure_once(
        &mut self,
        directory: &Path,
        protocol: BrokerSessionProtocolV1,
        role: BrokerSessionDurableEndpointV1,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Result<(), FloorErrorV1> {
        self.configure_with_custody_once(
            directory,
            protocol,
            role,
            launch_image,
            CredentialReadCustodyV1::Retained,
        )
    }

    pub(super) fn configure_with_custody_once(
        &mut self,
        directory: &Path,
        protocol: BrokerSessionProtocolV1,
        role: BrokerSessionDurableEndpointV1,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.launch_image = launch_image;
        self.result = Some(self.configure(directory, protocol, role, custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    fn configure(
        &mut self,
        directory: &Path,
        protocol: BrokerSessionProtocolV1,
        role: BrokerSessionDurableEndpointV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if protocol != BrokerSessionProtocolV1::Storage {
            if self.launch_image.is_some() {
                return Err(FloorErrorV1::Provisioning);
            }
            if matches!(directory.to_str(), Some(
                "/var/lib/aos/sandboxd/broker-session/storage"
                    | "/var/lib/aos/sandbox-storage/broker-session"
            )) {
                return Err(FloorErrorV1::Provisioning);
            }
            self.floor = Some(BrokerFloorV1 {
                state: FloorStateV1::NotScoped,
            });
            return Ok(());
        }
        let endpoint = match role {
            BrokerSessionDurableEndpointV1::Client => FloorEndpointV1::ControllerStorageClient,
            BrokerSessionDurableEndpointV1::Broker => FloorEndpointV1::StorageBroker,
        };
        let fixed = match endpoint {
            FloorEndpointV1::ControllerStorageClient => "/var/lib/aos/sandboxd/broker-session/storage",
            FloorEndpointV1::StorageBroker => "/var/lib/aos/sandbox-storage/broker-session",
        };
        if directory != Path::new(fixed) {
            #[cfg(test)]
            {
                self.floor = Some(BrokerFloorV1::test_not_scoped());
                return Ok(());
            }
            #[cfg(not(test))]
            {
                return Err(FloorErrorV1::Provisioning);
            }
        }

        self.mode = Some(match custody {
            CredentialReadCustodyV1::Ordinary => ModePinV1::open(endpoint)?,
            CredentialReadCustodyV1::Retained => {
                ModePinV1::open_retaining(endpoint, &mut self.mode_original)?
            }
        });
        let mode = self.mode.as_ref().ok_or(FloorErrorV1::Provisioning)?.mode();
        match mode {
            ImageFloorModeV1::LegacyClosed => {
                if self.launch_image.is_some() {
                    return Err(FloorErrorV1::Provisioning);
                }
                self.absence.observe_once(directory, custody)?;
                let mode = self.mode.take().ok_or(FloorErrorV1::Provisioning)?;
                self.floor = Some(BrokerFloorV1 {
                    state: FloorStateV1::Legacy {
                        mode,
                        cold: LegacyColdIntervalV1::new(),
                    },
                });
            }
            ImageFloorModeV1::Required => {
                match custody {
                    CredentialReadCustodyV1::Ordinary => {
                        super::super::backend::confinement::require_owner(endpoint)?;
                    }
                    CredentialReadCustodyV1::Retained => {
                        self.confinement.capture_once(endpoint, custody)?;
                    }
                }
                self.provision = Some(match custody {
                    CredentialReadCustodyV1::Ordinary => ProvisionPinV1::open(endpoint)?,
                    CredentialReadCustodyV1::Retained => {
                        ProvisionPinV1::open_retaining(endpoint, &mut self.provision_original)?
                    }
                });
                // Keep both original pins until every preceding admission,
                // including actual launch presence, has completed.
                if self.launch_image.is_none() {
                    return Err(FloorErrorV1::Unavailable);
                }
                let mode = self.mode.take().ok_or(FloorErrorV1::Provisioning)?;
                let provision = match self.provision.take() {
                    Some(provision) => provision,
                    None => {
                        self.mode = Some(mode);
                        return Err(FloorErrorV1::Provisioning);
                    }
                };
                let launch_image = self.launch_image.take().ok_or(FloorErrorV1::Unavailable)?;
                self.floor = Some(BrokerFloorV1 {
                    state: FloorStateV1::Required {
                        mode,
                        provision,
                        launch_image,
                        attached: BrokerAttachmentAttemptV1::fresh(),
                    },
                });
            }
        }
        Ok(())
    }

    pub(in crate::recovery::journal) fn take_floor_once(&mut self) -> Option<BrokerFloorV1> {
        if self.taken || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        let floor = self.floor.take()?;
        self.taken = true;
        Some(floor)
    }

    pub(in crate::recovery::journal) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.mode_original.failure()
            .or_else(|| self.absence.failure())
            .or_else(|| self.confinement.failure())
            .or_else(|| self.provision_original.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error))
    }
}
