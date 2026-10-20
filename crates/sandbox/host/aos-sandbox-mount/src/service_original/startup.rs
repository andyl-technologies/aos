//! Runs the fixed configuration, Mount state Journal and Store startup recipes.

use std::path::Path;

use aos_sandbox_mount_native::{MountCapturedJournalOpenModeV1, JournalLimits};

use super::*;

const CONFIGURATION: &str = "/run/credentials/aos-sandbox-mountd.service";
const CATALOG: &str = crate::destination_slot::SELECTED_CATALOG_V2;

impl MountAttachmentAnchorServiceOriginalV4 {
    fn fixed_startup_shape() -> std::result::Result<ResourceVector, MountServiceGeometryErrorV4> {
        ProtectedBrokerAuthorityConfiguration::receiving_demand_v1()?
            .checked_add(MountStateCapturedJournalOpenV4::fixed_preparation_demand()?)?
            .checked_add(DestinationSlotStartupOriginalV4::fixed_receiving_demand_v4()?)
            .map_err(Into::into)
    }

    pub(super) fn capture_startup_inner(&mut self) -> Result<()> {
        self.fixed = Some(Self::fixed_startup_shape());
        let fixed = match self.fixed.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(fixed) => fixed,
            None => {
                self.first.get_or_insert(Failure::Geometry);
                return Err(closed("Mount fixed startup geometry refused"));
            }
        };
        // The first native before/after and all fixed configuration/opening
        // destinations are paid before any subsequent native resource exists.
        self.funding[0] = Some(self.common.require_startup_representation_v4(fixed));
        if !matches!(self.funding[0], Some(Ok(()))) {
            self.first.get_or_insert(Failure::Funding);
            return Err(closed("Mount startup fixed receiving refused"));
        }
        self.admitted = fixed;
        self.startup_body = Some(self.capture_paid_startup());
        let body = if matches!(self.startup_body, Some(Ok(()))) { Ok(()) } else { Err(Closed) };
        self.startup_after = Some(self.common.finish_startup_native_once_v4(body));
        if !matches!(self.startup_after, Some(Ok(()))) {
            self.first.get_or_insert(Failure::After);
        }
        if self.first.is_some() { return Err(closed("Mount startup and independent native post remain closed")); }

        // Both moves are native-infallible after the whole original startup
        // conjunction. They cannot issue a role, Session or semantic permit.
        self.store = self.store_opening.take_completed_once_v4();
        // The same captured Session and admitted listener remain in their
        // opaque originals. The separate paid cold-opening interval performs
        // their owning handoff, with its own independently owed native after.
        if self.store.is_none() {
            self.first.get_or_insert(Failure::Transfer);
            return Err(closed("Mount completed native startup handoff is absent"));
        }
        self.ready = true;
        Ok(())
    }

    fn capture_paid_startup(&mut self) -> Result<()> {
        self.native_before = Some(self.common.begin_startup_native_once_v4());
        if !matches!(self.native_before, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Before);
            return Err(closed("Mount startup native before refused"));
        }
        self.configuration_result = Some(self.configuration.capture_mount_once_v4(Path::new(CONFIGURATION)));
        if !matches!(self.configuration_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Configuration);
            return Err(closed("Mount fixed configuration retained a refusal"));
        }
        let configuration = match self.configuration.take_configuration_once() {
            Some(configuration) => configuration,
            None => {
                self.first.get_or_insert(Failure::Configuration);
                return Err(closed("Mount completed configuration is absent"));
            }
        };
        let (authority, credentials) = MountAuthorityV1::from_captured_mount_configuration_v4(configuration);
        self.authority = Some(authority);
        self.credentials = Some(credentials);

        self.state_opening.prepare_once(JournalLimits::default(), MountCapturedJournalOpenModeV1::CreateAndRepair);
        self.state_extent = Some(match self.state_opening.captured_extent() {
            Some(extent) => extent_shape(extent),
            None => {
                self.first.get_or_insert(Failure::State);
                return Err(closed("Mount state opening retained a refusal"));
            }
        });
        let state = match self.state_extent.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(state) => state,
            None => {
                self.first.get_or_insert(Failure::Geometry);
                return Err(closed("Mount state replay geometry refused"));
            }
        };
        self.admit_startup_growth(state, 1)?;
        self.state_opening.replay_once();
        match self.state_opening.take_opened() {
            Some((journal, report)) => { self.state = Some(journal); self.state_report = Some(report); }
            None => {
                self.first.get_or_insert(Failure::State);
                return Err(closed("Mount state replay/independent posts refused"));
            }
        }

        // Session's private parent/custody are created by the retained
        // same-main installer in the distinct cold-opening interval. Its
        // actual captured Journal remains inert here; no preprovisioned path
        // or helper command is assumed and no future native work is prepaid
        // twice under this earlier startup interval.
        let journal = self.state.as_ref().ok_or_else(|| closed("Mount original state Journal is absent"))?;
        self.store_extent = Some(DestinationSlotStartupOriginalV4::reached_receiving_demand_v4(journal));
        let store = match self.store_extent.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(store) => store,
            None => {
                self.first.get_or_insert(Failure::Geometry);
                return Err(closed("Mount complete Store recovery geometry refused"));
            }
        };
        self.admit_startup_growth(store, 2)?;
        let journal = self.state.as_ref().ok_or_else(|| closed("Mount original state Journal is absent"))?;
        self.store_result = Some(self.store_opening.open_once_v4(Path::new(CATALOG), 0, journal));
        if !matches!(self.store_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Store);
            return Err(closed("Mount Store recovery retained its native/model refusal"));
        }
        self.listener_result = Some(self.common.capture_service_listener_once_v4(&mut self.listener_opening));
        if !matches!(self.listener_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Transfer);
            return Err(closed("Mount original listener admission refused"));
        }
        Ok(())
    }

    fn admit_startup_growth(&mut self, growth: ResourceVector, stage: usize) -> Result<()> {
        // All prior replay/configuration/native owners remain resident. SUM
        // their representation; no phase maximum or previous-file credit.
        self.growth = Some(self.admitted.checked_add(growth));
        let complete = match self.growth.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(complete) => complete,
            None => {
                self.first.get_or_insert(Failure::Geometry);
                return Err(closed("Mount startup cumulative representation overflow"));
            }
        };
        let slot = self.funding.get_mut(stage).ok_or_else(|| closed("Mount startup fixed stage is unavailable"))?;
        *slot = Some(self.common.require_startup_representation_v4(complete));
        if !matches!(slot, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Funding);
            return Err(closed("Mount startup cumulative receiving refused"));
        }
        self.admitted = complete;
        Ok(())
    }
}

fn extent_shape(extent: &aos_sandbox_mount_native::MountJournalReplayExtentV1)
    -> std::result::Result<ResourceVector, MountServiceGeometryErrorV4>
{
    let native = extent.dominant_native_receiving_demand_v1()?;
    let semantic = extent.dominant_semantic_receiving_demand_v1()?;
    native.checked_add(semantic).map_err(Into::into)
}
