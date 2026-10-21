//! Retains independent administrative originals beside the saved Root role tuple.
//!
//! The same fixed native credential engine captures both issuer files. Its
//! complete failed prefix stays here, including failures before a tuple can be
//! decoded. Neither an accepted packet nor a saved floor supplies a trust root.

use std::error::Error;

use aos_sandbox_broker::systemd_credentials::RootCurrentIssuerCredentialCustodyV1;
use aos_sandbox_model::{ObjectDigest, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::replay::root_genesis_pins;
use aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1;
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;

use crate::controller_readback::PinnedControllerHoldSignerV1;
use crate::journal_keys::{CONTROLLER_HOLD_PIN_KEY, SIGNER_PINS_KEY, SOURCE_HOLD_PIN_KEY};
use crate::native::journal::RootPolicyJournalV1;

use super::error::RootAuthorityErrorV1;

use crate::root_role_pins_data::{RootRolePinsDataErrorV1, RootRolePinsDataV1 as RolePinsDataV1};

pub(super) struct RootAuthorityPinsOriginalV1 {
    issuers: RootCurrentIssuerCredentialCustodyV1,
    parsed: Option<Result<RolePinsDataV1, RootAuthorityErrorV1>>,
    capture: Option<Result<(), ()>>,
    post: Option<Result<(), ()>>,
    entered: bool,
    reentered: bool,
}

impl RootAuthorityPinsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            issuers: RootCurrentIssuerCredentialCustodyV1::new(),
            parsed: None,
            capture: None,
            post: None,
            entered: false,
            reentered: false,
        }
    }

    // The genuine enclosing original composes this before constructing the
    // parent. Fixed arrays, SHA state and returned tuple coexist with custody.
    pub(super) fn fixed_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<RolePinsDataV1>()
            .checked_mul(3)?
            .checked_add(
                std::mem::size_of::<Result<RolePinsDataV1, RootAuthorityErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<[u8; 488]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<[u8; 120]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Vec<u8>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)?;
        // The enclosing Authority constructor already prices this destination
        // and its embedded issuer header. Retain the issuer native backing and
        // the actual decode/return planes, without charging that header again.
        let header =
            u64::try_from(std::mem::size_of::<RootCurrentIssuerCredentialCustodyV1>()).ok()?;
        RootCurrentIssuerCredentialCustodyV1::dominant_demand()?
            .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, header))
            .ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
            .ok()
    }

    pub(super) fn capture_once(&mut self, journal: &RootPolicyJournalV1) {
        if self.entered {
            self.reentered = true;
            return;
        }
        self.entered = true;
        self.capture = Some(self.issuers.capture_once());
        if matches!(self.capture, Some(Ok(()))) {
            self.parsed = Some(self.decode_actual(journal));
        }
    }

    pub(super) fn has_positive_capture_v1(&self) -> bool {
        matches!(self.capture, Some(Ok(())))
            && matches!(self.parsed, Some(Ok(_)))
            && !self.reentered
    }

    // This is the same independently owed native final readback, including
    // after an entered failed capture. A late failure cannot replace parsed's
    // earlier exact codec/role cause. The enclosing operation runs it on unwind.
    pub(super) fn finish_once(&mut self) {
        if self.post.is_some() {
            self.reentered = true;
            return;
        }
        self.post = Some(self.issuers.recheck_once());
    }

    fn decode_actual(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<RolePinsDataV1, RootAuthorityErrorV1> {
        journal.require_native_original()?;
        let [seed, authorization] = self.issuers.bytes().ok_or(RootAuthorityErrorV1::Stale)?;
        crate::root_role_pins_data::role_pins_from_rows_v1(
            journal.read_view().historical_view(),
            seed,
            authorization,
        )
        .map_err(|cause| match cause {
            RootRolePinsDataErrorV1::NonCanonical => RootAuthorityErrorV1::NonCanonical,
            RootRolePinsDataErrorV1::Stale => RootAuthorityErrorV1::Stale,
            RootRolePinsDataErrorV1::Data(cause) => cause.into(),
            RootRolePinsDataErrorV1::Controller(cause) => cause.into(),
            RootRolePinsDataErrorV1::Source(cause) => cause.into(),
        })
    }

    pub(super) fn ready(&self) -> bool {
        self.entered
            && !self.reentered
            && matches!(self.capture, Some(Ok(())))
            && matches!(self.parsed, Some(Ok(_)))
            && matches!(self.post, Some(Ok(())))
            && self.issuers.failure().is_none()
    }

    fn data(&self) -> Result<&RolePinsDataV1, RootAuthorityErrorV1> {
        if !self.ready() {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.parsed
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(RootAuthorityErrorV1::Stale)
    }

    pub(super) fn recheck(
        &self,
        journal: &RootPolicyJournalV1,
        observation: &mut aos_sandbox_broker::systemd_credentials::RootCurrentIssuerReadbackOriginalV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        journal.require_native_original()?;
        let data = self.data()?;
        observation
            .observe_once(&self.issuers)
            .map_err(|()| RootAuthorityErrorV1::Stale)?;
        if journal.get(RecordNamespace::DesiredState, CONTROLLER_HOLD_PIN_KEY)
            != Some(&data.encoded_data_v1()[176..256])
            || journal.get(RecordNamespace::DesiredState, SOURCE_HOLD_PIN_KEY)
                != Some(&data.encoded_data_v1()[256..336])
            || journal.get(RecordNamespace::DesiredState, SIGNER_PINS_KEY)
                != Some(&data.encoded_data_v1()[336..456])
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn record_bytes(&self) -> Result<&[u8; 488], RootAuthorityErrorV1> {
        Ok(self.data()?.encoded_data_v1())
    }

    pub(super) fn controller(&self) -> Result<&PinnedControllerHoldSignerV1, RootAuthorityErrorV1> {
        Ok(self.data()?.controller_data_v1())
    }

    pub(super) fn source(&self) -> Result<&PinnedSourceHoldReadbackSignerV1, RootAuthorityErrorV1> {
        Ok(self.data()?.source_data_v1())
    }

    pub(super) fn digest(&self) -> Result<ObjectDigest, RootAuthorityErrorV1> {
        root_genesis_pins::role_tuple_digest(self.record_bytes()?).map_err(Into::into)
    }

    pub(super) fn verify_administrative_input(
        &self,
        acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        root_genesis_pins::verify_administrative_input_data_v1(self.record_bytes()?, acceptance)
            .map_err(|cause| match cause {
                root_genesis_pins::RootAdministrativePinsDataErrorV1::Data(cause) => cause.into(),
                root_genesis_pins::RootAdministrativePinsDataErrorV1::Stale => {
                    RootAuthorityErrorV1::Stale
                }
            })
    }

    pub(super) fn verify_first_source_successor_v2(
        &self,
        packet: &aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2,
    ) -> Result<(), RootAuthorityErrorV1> {
        root_genesis_pins::verify_retained_first_source_successor_v2(self.record_bytes()?, packet)
            .map_err(Into::into)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.issuers
            .capture_failure()
            .map(|error| error as _)
            .or_else(|| {
                self.parsed
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.issuers.post_failure().map(|error| error as _))
    }
}
