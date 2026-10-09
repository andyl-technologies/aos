//! Scoped live opaque authority and original preparation for ARM root computation.
//!
//! Exactness means preserved native state and checked event mediation. It does
//! not imply hardware timing fidelity, Linux application readiness, arbitrary
//! devices, or admission of externally supplied model assets.

use crucible_node_contract::{ContentRef, HashRef, Phase, Position, U64};

use super::{
    ArmRootCapturedImage, ArmRootNativeProcess, ArmRootPreparedSession, ArmRootProcessClosure,
};
use crate::ProviderError;

/// Seals the installed event controls to one independently audited live owner.
#[derive(Debug)]
pub struct ArmRootExactAuthority {
    pid: u32,
    start_ticks: String,
    source_scope: HashRef,
    maximum_microsteps: U64,
    evidence: ContentRef,
    bytes: Vec<u8>,
}

impl ArmRootExactAuthority {
    /// Returns the source-installed finite same-instant coordinate budget.
    pub fn maximum_microsteps(&self) -> U64 {
        self.maximum_microsteps
    }

    /// Borrows unchanged independent opaque evidence without promoting diagnostics.
    pub fn evidence(&self) -> (&ContentRef, &[u8]) {
        (&self.evidence, &self.bytes)
    }

    pub(crate) fn require_live(&self, process: &ArmRootNativeProcess) -> Result<(), ProviderError> {
        self.evidence.verify(&self.bytes)?;
        let custody = process
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM exact custody absent"))?;
        let group = custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM exact kernel peer absent"))?;
        group.require_live()?;
        if group.identity() != (self.pid, self.start_ticks.as_str())
            || custody.launch.scope()? != self.source_scope
        {
            return Err(ProviderError::Correlation(
                "ARM exact authority names another incarnation",
            ));
        }
        Ok(())
    }
}

impl ArmRootNativeProcess {
    /// Qualifies installed exact event controls with current independent byte closure.
    ///
    /// The installed policy is the fixed root model and its byte-identical tested
    /// event mediator. This authority is private native scope; common public Ready
    /// still requires its separate original preparation and capability contract.
    ///
    /// # Errors
    /// Refuses stale certificates, changed images/profile, unsupported clocks,
    /// unrepresentable microsteps or unresolved original control custody.
    pub fn qualify_exact(
        &self,
        image: &ArmRootCapturedImage,
        certificate: &ArmRootProcessClosure,
    ) -> Result<ArmRootExactAuthority, ProviderError> {
        certificate.verify_image(image)?;
        certificate.require_current(self)?;
        let launch = self.launch()?;
        let installed = super::arm_root_installed::InstalledArmRootMechanism::load()?;
        if installed.manifest_content()? != launch.profile
            || launch.metadata["clock"]["native_tick_ps"] != serde_json::json!("1")
            || launch.metadata["clock"]["mapping_id"]
                != serde_json::json!("gem5/even-reaction-odd-publication-v1")
        {
            return Err(ProviderError::Correlation(
                "ARM installed clock/mediator binding differs",
            ));
        }
        let maximum: U64 =
            serde_json::from_value(launch.metadata["clock"]["maximum_microsteps"].clone())
                .map_err(|_| ProviderError::Frame("ARM installed closure cap"))?;
        if maximum.get() != 1_000_000 || self.boundary.logical_position.microstep >= maximum {
            return Err(ProviderError::Correlation(
                "ARM exact coordinate exceeds fixed cap",
            ));
        }
        Ok(ArmRootExactAuthority {
            pid: certificate.pid,
            start_ticks: certificate.start_ticks.clone(),
            source_scope: certificate.source_scope.clone(),
            maximum_microsteps: maximum,
            evidence: certificate.evidence.clone(),
            bytes: certificate.bytes.clone(),
        })
    }

    /// Borrows original preparation only under authentic current owner authority.
    ///
    /// A reconstruction at tick zero remains reconstructed. It cannot acquire
    /// original preparation by presenting an old packet or resetting a cursor.
    ///
    /// # Errors
    /// Refuses foreign authority, restored construction, any modeled history,
    /// changed native session or tampered original wire/transcript bytes.
    pub fn initial_prepared_session(
        &self,
        authority: &ArmRootExactAuthority,
    ) -> Result<&ArmRootPreparedSession, ProviderError> {
        authority.require_live(self)?;
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(ProviderError::Frame("ARM validated preparation absent"))?;
        let custody = self
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM original session absent"))?;
        let group = custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM original child absent"))?;
        prepared.packet.verify(&prepared.bytes)?;
        prepared.transcript.verify(&prepared.transcript_bytes)?;
        if !matches!(
            prepared.origin,
            super::arm_root_process::ArmRootOrigin::Original
        ) || group.identity() != (prepared.pid, prepared.start_ticks.as_str())
            || custody.launch.scope()? != prepared.source_scope
            || self.boundary.ordinal.get() != 0
            || self.boundary.tick.get() != 0
            || self.boundary.logical_position.time_ps.get() != 0
            || self.boundary.logical_position.microstep.get() != 0
            || self.boundary.logical_position.phase != Phase::BoundaryControl
            || !self.completed.is_empty()
            || self.pending.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
        {
            return Err(ProviderError::Correlation(
                "ARM session is not genuine original preparation",
            ));
        }
        Ok(prepared)
    }

    /// Borrows genuine reconstructed session bytes under its own fresh authority.
    ///
    /// This authenticates reconstructed custody and its actual source capture.
    /// It never converts a restored-at-zero peer into original preparation.
    ///
    /// # Errors
    /// Refuses original construction, foreign capture lineage, changed kernel or
    /// session scope, tampered packets/transcripts or unresolved native control.
    pub fn restored_prepared_session(
        &self,
        authority: &ArmRootExactAuthority,
        source_capture: &crucible_node_contract::Id,
    ) -> Result<&ArmRootPreparedSession, ProviderError> {
        authority.require_live(self)?;
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(ProviderError::Frame("ARM validated preparation absent"))?;
        let custody = self
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM restored session absent"))?;
        let group = custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM restored child absent"))?;
        prepared.packet.verify(&prepared.bytes)?;
        prepared.transcript.verify(&prepared.transcript_bytes)?;
        if !matches!(&prepared.origin, super::arm_root_process::ArmRootOrigin::Restored {
            source_capture: actual } if actual == source_capture)
            || group.identity() != (prepared.pid, prepared.start_ticks.as_str())
            || custody.launch.scope()? != prepared.source_scope
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
        {
            return Err(ProviderError::Correlation(
                "ARM session lacks genuine reconstructed lineage",
            ));
        }
        Ok(prepared)
    }

    /// Returns the authentic logical cursor without advancing a native event.
    pub fn logical_position(&self) -> Position {
        self.boundary.logical_position
    }

    /// Returns the earliest possible native serial publication under closed inputs.
    ///
    /// # Errors
    /// Refuses foreign owner authority or exhausted same-time coordinates.
    pub fn next_publication_bound(
        &self,
        authority: &ArmRootExactAuthority,
    ) -> Result<Option<Position>, ProviderError> {
        authority.require_live(self)?;
        if let Some(publication) = self
            .pending
            .as_ref()
            .and_then(|id| self.completed.get(id))
            .and_then(|outcome| outcome.completion())
            .and_then(|prefix| prefix.publications.first())
        {
            let ordinal = publication.tick_ordinal.get();
            let microstep = ordinal
                .checked_sub(1)
                .and_then(|value| value.checked_mul(2))
                .and_then(|value| value.checked_add(1))
                .filter(|value| *value < authority.maximum_microsteps.get())
                .ok_or(ProviderError::Frame(
                    "ARM retained serial coordinate exceeds finite cap",
                ))?;
            return Ok(Some(Position::new(
                publication.tick,
                microstep.into(),
                Phase::Publication,
            )));
        }
        self.boundary
            .next_reaction(authority.maximum_microsteps)?
            .map(|reaction| {
                reaction
                    .reaction_publication(authority.maximum_microsteps)
                    .map_err(ProviderError::from)
            })
            .transpose()
    }
}
