//! Checked extension over a sealed, independently authenticated TPM transport.
//!
//! The private fixed-image ESYS child authenticates fresh responses under a
//! salted HMAC session pinned to the provisioned salt-key Name and retained
//! device. Plain tool stdout, caller scalars, PCR sealing, or an emulator cannot
//! fill this seam.

pub(crate) use super::format::NV_ATTRIBUTES_WRITTEN;
use super::{FloorErrorV1, FloorIntentV1, FloorProfileV1};

pub(super) mod confinement;
mod helper_protocol;
mod image;
mod physical;
mod service_policy;

pub(super) use physical::PhysicalTpmNvIoV1;

pub(crate) use confinement::{
    require_helper as require_broker_floor_helper_v1,
    require_owner as require_broker_floor_owner_v1,
};
pub(crate) use helper_protocol::{
    HelperObservationV1, HelperOperationV1, LOCK_ACK_BYTES, RESPONSE_BYTES, decode_response_v2,
    encode_auth_v2, encode_hello_v2, encode_request_v2, require_lock_ack_v2,
};
pub(crate) use image::MeasuredHelperImageV1;
pub(crate) use physical::BrokerPhysicalOpenV1;
pub(crate) use service_policy::RetainedFloorServicePolicyV1;

/// Seals the transport boundary to this module's sole physical producer.
mod sealed {
    pub(super) trait Sealed {}
}

/// Returns fresh authenticated TPM state, not cached subprocess output.
pub(super) trait AuthenticatedTpmNvIoV1: sealed::Sealed {
    fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1>;

    /// Ambiguity includes a lost successful reply; callers always read back.
    ///
    /// A retained ESYS producer must finish or fence an outstanding command
    /// before returning: the subsequent authenticated read cannot overtake an
    /// earlier queued extension. A transport unable to establish that ordering
    /// must fail its read, not expose an old value as retry authority.
    fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1>;
}

pub(crate) struct AuthenticatedNvObservationV1 {
    pub(crate) salt_key_name_digest: [u8; 32],
    pub(crate) index: u32,
    pub(crate) name: [u8; 34],
    pub(crate) name_algorithm: u16,
    pub(crate) attributes: u32,
    pub(crate) size: u16,
    pub(crate) empty_auth_policy: bool,
    pub(crate) value: [u8; 32],
}

/// Retains the fixed provisioning pin but grants no journal/readiness authority.
pub(super) struct TpmNvExtendFloorBackendV1<Io> {
    profile: FloorProfileV1,
    io: Io,
}

/// Resolves an ambiguous extension only through a fresh matching readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloorAdvanceV1 {
    NotAdvanced,
    Advanced,
}

impl<Io: AuthenticatedTpmNvIoV1> TpmNvExtendFloorBackendV1<Io> {
    #[cfg(test)]
    pub(super) fn into_test_io(self) -> Io {
        self.io
    }

    #[cfg(test)]
    pub(super) fn test_io(&mut self) -> &mut Io {
        &mut self.io
    }

    pub(super) fn open(profile: FloorProfileV1, io: Io) -> Result<Self, FloorErrorV1> {
        let mut backend = Self::retain(profile, io);
        backend.read()?;
        Ok(backend)
    }

    // The genuine production attempt parks this exact sealed IO before its
    // first authenticated read. This does not admit a profile or create IO.
    pub(super) fn retain(profile: FloorProfileV1, io: Io) -> Self {
        Self { profile, io }
    }

    pub(super) fn read(&mut self) -> Result<[u8; 32], FloorErrorV1> {
        let observed = self.io.read(self.profile.endpoint().nv_index())?;
        if observed.salt_key_name_digest != self.profile.salt_key_name_digest()
            || observed.index != self.profile.endpoint().nv_index()
            || observed.name != self.profile.nv_name()
            || observed.name_algorithm != 0x000b
            || observed.attributes != NV_ATTRIBUTES_WRITTEN
            || observed.size != 32
            || !observed.empty_auth_policy
            || observed.value == [0; 32]
        {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(observed.value)
    }

    /// Requires separately retained protected prepare bytes and exclusive custody.
    ///
    /// TPM NV_Extend is not a hardware compare-and-swap. The owner must keep
    /// the index credential exclusive, both journal flocks held, and recheck
    /// exact NV at every dependent send/effect. A competing authorized writer
    /// can cause denial, but cannot silently reset or replace this HEAD.
    #[cfg(test)]
    pub(super) fn advance(
        &mut self,
        prepared: FloorIntentV1,
    ) -> Result<FloorAdvanceV1, FloorErrorV1> {
        self.advance_with_held_cut(prepared, || Ok(()))
    }

    /// Rechecks the actual retained writers after fresh NV and before extending.
    pub(super) fn advance_with_held_cut(
        &mut self,
        prepared: FloorIntentV1,
        require_held_cut: impl FnOnce() -> Result<(), FloorErrorV1>,
    ) -> Result<FloorAdvanceV1, FloorErrorV1> {
        prepared.require_predecessor(self.profile, prepared.predecessor())?;
        let old = prepared.predecessor().nv_value();
        let target = prepared.target();
        match self.read()? {
            value if value == target.nv_value() => return Ok(FloorAdvanceV1::Advanced),
            value if value == old => {}
            _ => return Err(FloorErrorV1::Diverged),
        }

        require_held_cut()?;

        // Never blindly repeat an error: the command may already have extended.
        let _ambiguous_result = self
            .io
            .extend(self.profile.endpoint().nv_index(), &target.extend_input());
        match self.read()? {
            value if value == target.nv_value() => Ok(FloorAdvanceV1::Advanced),
            value if value == old => Ok(FloorAdvanceV1::NotAdvanced),
            _ => Err(FloorErrorV1::Diverged),
        }
    }
}

#[cfg(test)]
pub(super) mod fixture;
