//! Test-only TPM behavior, including ambiguous extension and damaged NV.
//!
//! This fake cannot be constructed by production code and does not stand in
//! for authenticated device/session or installed rollback qualification.

use super::*;
use crate::recovery::journal::tpm_floor::tests::floor_fixture;

#[derive(Clone, Copy)]
pub(in crate::recovery::journal::tpm_floor) enum ExtendBehavior {
    Success,
    LostReply,
    NotWritten,
    DeletedByPowerLoss,
    CompetingExtension,
}

pub(in crate::recovery::journal::tpm_floor) struct FakeTpm {
    profile: FloorProfileV1,
    value: Option<[u8; 32]>,
    attributes: u32,
    salt_key_name_digest: [u8; 32],
    behavior: ExtendBehavior,
    extensions: usize,
}

impl FakeTpm {
    pub(in crate::recovery::journal::tpm_floor) fn extensions(&self) -> usize {
        self.extensions
    }

    pub(in crate::recovery::journal::tpm_floor) fn set_behavior(
        &mut self,
        behavior: ExtendBehavior,
    ) {
        self.behavior = behavior;
    }

    pub(in crate::recovery::journal::tpm_floor) fn set_value(&mut self, value: Option<[u8; 32]>) {
        self.value = value;
    }
}

impl sealed::Sealed for FakeTpm {}

impl AuthenticatedTpmNvIoV1 for FakeTpm {
    fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        Ok(AuthenticatedNvObservationV1 {
            salt_key_name_digest: self.salt_key_name_digest,
            index,
            name: self.profile.nv_name(),
            name_algorithm: 0x000b,
            attributes: self.attributes,
            size: 32,
            empty_auth_policy: true,
            value: self.value.ok_or(FloorErrorV1::Unavailable)?,
        })
    }

    fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        assert_eq!(index, self.profile.endpoint().nv_index());
        self.extensions += 1;
        let old = self.value.ok_or(FloorErrorV1::Unavailable)?;
        let target = super::super::hash_parts(b"", &[&old, input]);
        match self.behavior {
            ExtendBehavior::Success => {
                self.value = Some(target);
                Ok(())
            }
            ExtendBehavior::LostReply => {
                self.value = Some(target);
                Err(FloorErrorV1::Unavailable)
            }
            ExtendBehavior::NotWritten => Err(FloorErrorV1::Unavailable),
            ExtendBehavior::DeletedByPowerLoss => {
                self.value = None;
                Err(FloorErrorV1::Unavailable)
            }
            ExtendBehavior::CompetingExtension => {
                self.value = Some(super::super::hash_parts(b"", &[&target, &[99; 32]]));
                Err(FloorErrorV1::Unavailable)
            }
        }
    }
}

pub(in crate::recovery::journal::tpm_floor) fn fake(
    profile: FloorProfileV1,
    value: [u8; 32],
    behavior: ExtendBehavior,
) -> FakeTpm {
    FakeTpm {
        profile,
        value: Some(value),
        attributes: NV_ATTRIBUTES_WRITTEN,
        salt_key_name_digest: profile.salt_key_name_digest(),
        behavior,
        extensions: 0,
    }
}

#[test]
fn tpm_floor_success_and_lost_reply_extend_only_once() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    for behavior in [ExtendBehavior::Success, ExtendBehavior::LostReply] {
        let mut backend = TpmNvExtendFloorBackendV1::open(
            profile,
            fake(profile, checkpoint.nv_value(), behavior),
        )
        .unwrap();

        assert_eq!(backend.advance(prepared), Ok(FloorAdvanceV1::Advanced));
        assert_eq!(backend.advance(prepared), Ok(FloorAdvanceV1::Advanced));
        assert_eq!(backend.io.extensions, 1);
        assert_eq!(backend.read().unwrap(), prepared.target().nv_value());
    }
}

#[test]
fn tpm_floor_unwritten_command_can_retry_only_exact_preparation() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    let mut backend = TpmNvExtendFloorBackendV1::open(
        profile,
        fake(profile, checkpoint.nv_value(), ExtendBehavior::NotWritten),
    )
    .unwrap();

    assert_eq!(backend.advance(prepared), Ok(FloorAdvanceV1::NotAdvanced));
    backend.io.behavior = ExtendBehavior::Success;
    assert_eq!(backend.advance(prepared), Ok(FloorAdvanceV1::Advanced));
    assert_eq!(backend.io.extensions, 2);
}

#[test]
fn tpm_floor_missing_changed_unwritten_and_orderly_tpm_remain_closed() {
    let (profile, checkpoint, _, _) = floor_fixture();
    let mut missing = fake(profile, checkpoint.nv_value(), ExtendBehavior::Success);
    missing.value = None;
    assert!(matches!(
        TpmNvExtendFloorBackendV1::open(profile, missing),
        Err(FloorErrorV1::Unavailable)
    ));

    for attributes in [
        super::super::format::NV_ATTRIBUTES_DEFINED,
        NV_ATTRIBUTES_WRITTEN | (1 << 26),
        NV_ATTRIBUTES_WRITTEN | (1 << 27),
        NV_ATTRIBUTES_WRITTEN | (1 << 1),
    ] {
        let mut wrong = fake(profile, checkpoint.nv_value(), ExtendBehavior::Success);
        wrong.attributes = attributes;
        assert!(matches!(
            TpmNvExtendFloorBackendV1::open(profile, wrong),
            Err(FloorErrorV1::Provisioning)
        ));
    }
    let mut cleared_or_replaced = fake(profile, checkpoint.nv_value(), ExtendBehavior::Success);
    cleared_or_replaced.salt_key_name_digest = [42; 32];
    assert!(matches!(
        TpmNvExtendFloorBackendV1::open(profile, cleared_or_replaced),
        Err(FloorErrorV1::Provisioning)
    ));
}

#[test]
fn tpm_floor_power_loss_deletion_and_competing_writer_never_auto_initialize() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    for behavior in [
        ExtendBehavior::DeletedByPowerLoss,
        ExtendBehavior::CompetingExtension,
    ] {
        let mut backend = TpmNvExtendFloorBackendV1::open(
            profile,
            fake(profile, checkpoint.nv_value(), behavior),
        )
        .unwrap();

        assert!(backend.advance(prepared).is_err());
        assert!(backend.advance(prepared).is_err());
        assert_eq!(backend.io.extensions, 1);
    }
}

#[test]
fn tpm_floor_fresh_read_rechecks_salt_key_and_nv_attributes() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    let mut backend = TpmNvExtendFloorBackendV1::open(
        profile,
        fake(profile, checkpoint.nv_value(), ExtendBehavior::Success),
    )
    .unwrap();
    backend.io.attributes |= 1 << 26;

    assert_eq!(backend.advance(prepared), Err(FloorErrorV1::Provisioning));
    assert_eq!(backend.io.extensions, 0);
}
