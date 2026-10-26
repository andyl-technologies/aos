//! Runs approved initial NV reconciliation through one genuine Source helper.
//!
//! The resident approval and actual main original are rejoined before effects.
//! Native replies remain in Source custody; these retained projections support
//! semantic comparison only. The same loan publishes only after final target
//! comparison and actual orderly helper retirement.

use crate::method46_initial_provisioning::{
    Method46InitialNvDataV1, Method46InitialRecoveryDataV1,
};
use crate::tpm_nv_custody::{NV_ATTRIBUTES_DEFINED, NV_ATTRIBUTES_WRITTEN};
use aos_sandbox_broker::fixed_tpm_helper_wire::HelperObservationV1;

use super::*;

pub(super) struct InitialNvInitializationOriginalV1 {
    entered: bool,
    setup: [Option<Result<(), Method46InitialStartupClosedV1>>; 4],
    reads: [Option<Result<HelperObservationV1, Method46InitialStartupClosedV1>>; 3],
    decision: Option<Result<Method46InitialRecoveryDataV1, Method46InitialDataErrorV1>>,
    closed: Option<Result<(), Method46InitialStartupClosedV1>>,
    published: Option<Result<(), Method46InitialStartupClosedV1>>,
    result: Option<Result<(), Method46InitialDataErrorV1>>,
}

impl InitialNvInitializationOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            setup: [None; 4],
            reads: std::array::from_fn(|_| None),
            decision: None,
            closed: None,
            published: None,
            result: None,
        }
    }
}

impl<'owner> Method46InitialProvisionDecodeOriginalV1<'owner> {
    /// Reconciles approved initial NV through this Source's prepared helper once.
    ///
    /// One driving loan spans measured birth, locks, AUTH, initial Read, optional
    /// sole Extend, final Read and orderly close/reaping. An exact matching
    /// Written value skips Extend. Every observation must match the fixed public
    /// area and Name. Source additionally compares fresh native main metadata
    /// immediately before each request after readiness waiting.
    ///
    /// The same Source then publishes the canonical checkpoint through fresh
    /// currentness, atomic exchange and file/directory durability frontiers while
    /// retaining both writer locks. No caller supplies observed NV, approval,
    /// auth, checkpoint or channel. Installed qualification remains separate.
    ///
    /// # Errors
    /// Refuses foreign/ended originals, missing durable approval/helper/locks,
    /// reentry, changed main/request, conflicting or malformed NV, or failed
    /// native custody, TPM exchange or original cleanup. Failure fences this
    /// startup and retains uncertainty rather than authorizing another Extend.
    pub fn reconcile_approved_initial_nv_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<(), Method46InitialDataErrorV1> {
        let result = (|| {
            let mut intent = self
                .intent
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            if std::mem::replace(&mut intent.nv.entered, true) {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            let result = (|| {
                let (request, approved) = self.current_approved_initial_request(main)?;
                if !matches!(intent.helper_result, Some(Ok(())))
                    || !matches!(intent.result, Some(Ok(())))
                    || !matches!(intent.native, Some(Ok(())))
                    || !matches!(intent.after, Some(Ok(())))
                    || !matches!(intent.locks_result, Some(Ok(())))
                    || intent.locks_after.is_some()
                {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                let InitialIntentPublicationOriginal { helper, nv, .. } = &mut *intent;
                let mut driver = helper
                    .as_mut()
                    .ok_or(Method46InitialDataErrorV1::Conflict)?
                    .drive_once_v1()
                    .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
                nv.setup[0] = Some(driver.start_child_once_v1());
                require_native_step(nv.setup[0])?;
                nv.setup[1] = Some(driver.handoff_locks_once_v1());
                require_native_step(nv.setup[1])?;
                nv.setup[2] = Some(driver.authenticate_held_index_once_v1());
                require_native_step(nv.setup[2])?;

                let (current, _) = self.current_approved_initial_request(main)?;
                if current != request {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                nv.setup[3] =
                    Some(driver.capture_initial_checkpoint_stage_once_v1(current.checkpoint()));
                require_native_step(nv.setup[3])?;

                nv.reads[0] = Some(driver.read_initial_nv_once_v1());
                let observed = classify_initial_observation(request, read_data(&nv.reads[0])?)?;
                let (current, _) = self.current_approved_initial_request(main)?;
                nv.decision = Some(approved.compare_recovery(current, observed));
                let decision = nv.decision.ok_or(Method46InitialDataErrorV1::Conflict)??;
                if decision == Method46InitialRecoveryDataV1::ExtendInitial {
                    // Rejoin resident approval with the same main before the
                    // Source's own wait-separated native main observation.
                    let (current, _) = self.current_approved_initial_request(main)?;
                    if current != request {
                        return Err(Method46InitialDataErrorV1::Conflict);
                    }
                    nv.reads[1] = Some(driver.extend_initial_nv_once_v1(current.extend_input()));
                    require_initial_target(request, read_data(&nv.reads[1])?)?;
                }

                let (current, _) = self.current_approved_initial_request(main)?;
                if current != request {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                nv.reads[2] = Some(driver.read_final_nv_once_v1());
                require_initial_target(request, read_data(&nv.reads[2])?)?;
                nv.closed = Some(driver.close_and_reap_initial_helper_once_v1());
                require_native_step(nv.closed)?;
                let (current, _) = self.current_approved_initial_request(main)?;
                if current != request {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                nv.published = Some(driver.publish_initial_checkpoint_once_v1());
                require_native_step(nv.published)?;
                let (current, _) = self.current_approved_initial_request(main)?;
                if current != request {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                Ok(())
            })();
            intent.nv.result = Some(result);
            result
        })();
        if result.is_err() {
            // All temporary helper/intent borrows end before independently owed
            // native posts. Failed child prefixes remain with the same Source.
            self.refuse_intent_and_finish_after();
        }
        result
    }

    fn current_approved_initial_request(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<
        (Method46InitialRequestDataV1, Method46InitialIntentDataV1),
        Method46InitialDataErrorV1,
    > {
        let request = self.request_for_main_original_data_v1(main)?;
        let approved = self
            .approval
            .try_borrow()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?
            .verified_intent()?;
        if approved.request() != request {
            return Err(Method46InitialDataErrorV1::Conflict);
        }
        Ok((request, approved))
    }
}

fn require_native_step(
    result: Option<Result<(), Method46InitialStartupClosedV1>>,
) -> Result<(), Method46InitialDataErrorV1> {
    result
        .ok_or(Method46InitialDataErrorV1::Conflict)?
        .map_err(|_| Method46InitialDataErrorV1::Conflict)
}

fn read_data(
    read: &Option<Result<HelperObservationV1, Method46InitialStartupClosedV1>>,
) -> Result<&HelperObservationV1, Method46InitialDataErrorV1> {
    read.as_ref()
        .and_then(|read| read.as_ref().ok())
        .ok_or(Method46InitialDataErrorV1::Conflict)
}

// DATA comparison only. The sole production caller obtains these bytes from
// its same live Source driver, whose actual native record stays resident.
fn classify_initial_observation(
    request: Method46InitialRequestDataV1,
    observed: &HelperObservationV1,
) -> Result<Method46InitialNvDataV1, Method46InitialDataErrorV1> {
    let written = match observed.attributes {
        NV_ATTRIBUTES_DEFINED => false,
        NV_ATTRIBUTES_WRITTEN => true,
        _ => return Err(Method46InitialDataErrorV1::Conflict),
    };
    let name = if written {
        request.profile.nv_name()
    } else {
        request.profile.defined_nv_name()
    };
    if observed.name != name
        || observed.name_algorithm != 0x000b
        || observed.size != 32
        || observed.policy_length != 0
        || (written && observed.value == [0; 32])
        || (!written && observed.value != [0; 32])
    {
        return Err(Method46InitialDataErrorV1::Conflict);
    }
    Ok(if written {
        Method46InitialNvDataV1::Written(observed.value)
    } else {
        Method46InitialNvDataV1::Unwritten
    })
}

fn require_initial_target(
    request: Method46InitialRequestDataV1,
    observed: &HelperObservationV1,
) -> Result<(), Method46InitialDataErrorV1> {
    if classify_initial_observation(request, observed)?
        != Method46InitialNvDataV1::Written(request.expected_nv())
    {
        return Err(Method46InitialDataErrorV1::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::method46_initial_provisioning::Method46InitialPurposeV1;

    fn request(purpose: Method46InitialPurposeV1) -> Method46InitialRequestDataV1 {
        let mut salt = [4; 34];
        salt[..2].copy_from_slice(&[0, 0x0b]);
        Method46InitialRequestDataV1::new(purpose, [1; 16], [2; 16], [3; 32], salt, 4, [5; 32])
            .unwrap()
    }

    fn observation(request: Method46InitialRequestDataV1, written: bool) -> HelperObservationV1 {
        HelperObservationV1 {
            name: if written {
                request.profile.nv_name()
            } else {
                request.profile.defined_nv_name()
            },
            name_algorithm: 0x000b,
            attributes: if written {
                NV_ATTRIBUTES_WRITTEN
            } else {
                NV_ATTRIBUTES_DEFINED
            },
            size: 32,
            policy_length: 0,
            value: if written {
                request.expected_nv()
            } else {
                [0; 32]
            },
        }
    }

    #[test]
    fn both_public_names_match_independent_tpm_public_encoding_vectors() {
        // SHA-256 of the fixed, big-endian TPMS_NV_PUBLIC fields, computed
        // independently from the production Name recipe for each attribute set.
        for (purpose, defined, written) in [
            (
                Method46InitialPurposeV1::ControllerStorageClient,
                "000b2922e0facfb64805f3bf3af070bee6876d4780012db8f66401c3c0527f9cff34",
                "000b1ed0ed8e68f053c45e3af51db9046cedc99519d8abec43142d3e78845db5e11e",
            ),
            (
                Method46InitialPurposeV1::StorageBroker,
                "000b52d36b65df6f2cb9b3cbf325efa9e2b300704ffc4159d0f2444c2c012e5a224e",
                "000bc84daa65453d8828d2628c8fc4d39c50f7bbccb179356fc53036861942bdd74d",
            ),
        ] {
            let request = request(purpose);
            assert_eq!(hex::encode(request.profile.defined_nv_name()), defined);
            assert_eq!(hex::encode(request.profile.nv_name()), written);
            assert_eq!(
                classify_initial_observation(request, &observation(request, false)),
                Ok(Method46InitialNvDataV1::Unwritten)
            );
            assert!(require_initial_target(request, &observation(request, true)).is_ok());
        }
    }

    #[test]
    fn every_name_byte_and_public_field_is_checked_before_classification() {
        for purpose in [
            Method46InitialPurposeV1::ControllerStorageClient,
            Method46InitialPurposeV1::StorageBroker,
        ] {
            let request = request(purpose);
            for written in [false, true] {
                for offset in 0..34 {
                    let mut observed = observation(request, written);
                    observed.name[offset] ^= 1;
                    assert!(classify_initial_observation(request, &observed).is_err());
                }
                for field in 0..5 {
                    let mut observed = observation(request, written);
                    match field {
                        0 => observed.name_algorithm ^= 1,
                        1 => observed.attributes ^= 1,
                        2 => observed.size += 1,
                        3 => observed.policy_length = 1,
                        4 => observed.value = if written { [0; 32] } else { [1; 32] },
                        _ => unreachable!(),
                    }
                    assert!(classify_initial_observation(request, &observed).is_err());
                }
            }
        }
    }

    #[test]
    fn matching_written_recovery_skips_extend_and_foreign_value_refuses() {
        for purpose in [
            Method46InitialPurposeV1::ControllerStorageClient,
            Method46InitialPurposeV1::StorageBroker,
        ] {
            let request = request(purpose);
            let key = SigningKey::from_bytes(&[6; 32]);
            let approval = Method46InitialIntentDataV1::from_approval(
                request,
                key.sign(&request.encode()).to_bytes(),
                key.verifying_key().to_bytes(),
            )
            .unwrap();

            let unwritten = observation(request, false);
            assert_eq!(
                approval.compare_recovery(
                    request,
                    classify_initial_observation(request, &unwritten).unwrap()
                ),
                Ok(Method46InitialRecoveryDataV1::ExtendInitial)
            );
            assert!(require_initial_target(request, &unwritten).is_err());

            let mut written = observation(request, true);
            assert_eq!(
                approval.compare_recovery(
                    request,
                    classify_initial_observation(request, &written).unwrap()
                ),
                Ok(Method46InitialRecoveryDataV1::CheckpointInitial)
            );
            written.value[0] ^= 1;
            assert_eq!(
                approval.compare_recovery(
                    request,
                    classify_initial_observation(request, &written).unwrap()
                ),
                Err(Method46InitialDataErrorV1::Conflict)
            );
            assert!(require_initial_target(request, &written).is_err());
        }
    }
}
