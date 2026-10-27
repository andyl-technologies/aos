//! Schedules the actual native NoApply peer under the original upper locks.
//!
//! Policy owns the complete admission307, peer/current and four post originals.
//! Domain retains actual transport types and the L/U acquisition boundary. No
//! completed result, prefix or financial proxy constructs native permission.

mod stages;
pub(crate) use stages::RootExecutionNoApplyStageReceivingV2;

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{
    RootPurposePeerPostV1 as Post, RootSelectedControllerPeerOriginalV1,
};
use aos_sandbox_model::ResourceVector;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_policy::native::RootNoApplyControllerPeerOriginalV2 as NativePeer;

use super::super::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

pub(crate) struct RootExecutionNoApplyControllerPeerReceivingV2<'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    native: Option<NativePeer<'startup>>,
    transport_shape: Option<
        Result<ResourceVector, crate::controller_resource_reservation::ResourceReservationErrorV1>,
    >,
    preparation: Option<Result<(), Error>>,
    capture: Option<Result<(), Error>>,
    after: Option<Result<(), Error>>,
    initial_settlement: Option<Result<(), Error>>,
    final_before: Option<Result<(), Error>>,
    final_current: Option<Result<(), Error>>,
    final_after: Option<Result<(), Error>>,
    final_settlement: Option<Result<(), Error>>,
    entered: bool,
    complete: bool,
    closed: Option<Error>,
}

impl<'startup> RootExecutionNoApplyControllerPeerReceivingV2<'startup> {
    pub(in crate::normal_root) fn new(startup: &'startup ProductionNormalRootStartupV1) -> Self {
        Self {
            startup,
            native: None,
            transport_shape: None,
            preparation: None,
            capture: None,
            after: None,
            initial_settlement: None,
            final_before: None,
            final_current: None,
            final_after: None,
            final_settlement: None,
            entered: false,
            complete: false,
            closed: None,
        }
    }

    // The actual listener's fixed Stage pays these before constructing the
    // accepted-flight variant or entering any native purpose factory.
    pub(crate) fn construction_control_bytes_v2() -> Option<usize> {
        // new's returned/resident carrier is distinct from the native peer
        // returned by the real bridge. Neither is inferred from field slack.
        let construction = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<&ProductionNormalRootStartupV1>().checked_mul(2)?)?
            .checked_add(NativePeer::construction_control_bytes_v2()?)?
            .checked_add(stages::RootExecutionNoApplyStageReceivingV2::construction_control_bytes_v2()?)?
            .checked_add(crate::controller_resource_reservation::RootReceivingOriginalV1::
                native_no_apply_bridge_control_bytes_v2()?)?
            .checked_add(aos_sandbox_broker::receiving::RootStartupNativeOriginalV1::
                selected_original_borrow_control_bytes_v1()?)?;

        // capture and final posts retain their stream argument separately;
        // settlement and the stage view retain their mutable entry borrows.
        let phases = size_of::<(&mut Self, &RetainedUnixStream)>()
            .checked_add(size_of::<Result<(), Error>>())?
            .checked_mul(4)?
            .checked_add(
                size_of::<&mut Self>()
                    .checked_add(size_of::<Result<(), Error>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<&mut Self>().checked_mul(2)?)?;
        let checks = size_of::<&Self>()
            .checked_add(size_of::<Result<(), Error>>())?
            .checked_mul(2)?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<
                        Result<&RootSelectedControllerPeerOriginalV1<'static>, Error>,
                    >())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(&Self, &ProductionNormalRootStartupV1)>()
                    .checked_add(size_of::<Result<(), Error>>())?
                    .checked_mul(2)?,
            )?;
        let diagnostics = size_of::<&Self>()
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>())?
            .checked_mul(4)?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<
                        Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'static>>,
                    >())?
                    .checked_mul(2)?,
            )?;

        // Four actual short-guard closures (prepare, admission-after and two
        // final posts) return the original upper typed Result independently.
        let computations = size_of::<(
            &mut Self,
            &mut super::super::receiving_guard::RootReceivingGuardV1<'static>,
        )>()
        .checked_add(size_of::<Result<(), Error>>())?
        .checked_mul(2)?
        .checked_add(
            size_of::<&mut Self>()
                .checked_add(size_of::<Result<(), Error>>())?
                .checked_mul(8)?,
        )?
        .checked_add(size_of::<Result<NativePeer<'static>, Error>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<&NativePeer<'static>, Error>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<&mut NativePeer<'static>, Error>>().checked_mul(2)?)?
        .checked_add(
            size_of::<
                Result<
                    ResourceVector,
                    crate::controller_resource_reservation::ResourceReservationErrorV1,
                >,
            >()
            .checked_mul(2)?,
        )?
        .checked_add(size_of::<ResourceVector>().checked_mul(2)?)?;
        construction
            .checked_add(phases)?
            .checked_add(checks)?
            .checked_add(diagnostics)?
            .checked_add(computations)
    }

    pub(in crate::normal_root) fn capture_once_v1(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), Error> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.entered = true;
        self.preparation = Some((|| {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = (|| {
                // Compute this still-upper quote INSIDE the original L/U
                // interval. A pure quote refusal must deny the same original
                // before another shared debit can pass that boundary.
                self.transport_shape = Some(
                    crate::policy_compiler::execution_no_apply_root::transport::
                        transport_receiving_demand_v2(),
                );
                let upper = match self.transport_shape.as_ref() {
                    Some(Ok(geometry)) => *geometry,
                    _ => return Err(Error::Service),
                };
                let prepared = receiving
                    .original_mut_v1()
                    .prepare_native_no_apply_peer_v2(self.startup, upper);
                match prepared {
                    Ok(native) => {
                        // Retain the WHOLE entered negative owner before
                        // releasing the same original receiving interval.
                        self.native = Some(native);
                        self.native
                            .as_ref()
                            .ok_or(Error::Service)?
                            .require_prepared_v2()
                            .map_err(Into::into)
                    }
                    Err(cause) => Err(cause),
                }
            })();
            receiving.finish_returned_v1(returned)
        })());
        if matches!(self.preparation, Some(Ok(()))) {
            self.capture = Some(
                self.native
                    .as_mut()
                    .ok_or(Error::Service)?
                    .capture_once_v2(stream)
                    .map_err(Into::into),
            );
        }
        // Admission-after remains owed after native capture or admission error.
        self.after = Some((|| {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = receiving
                .original_mut_v1()
                .finish_native_no_apply_capture_post_v2(
                    self.native.as_mut().ok_or(Error::Service)?,
                );
            receiving.finish_returned_v1(returned)
        })());
        if matches!(self.capture, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && self.primary_failure_v1().is_none()
        {
            self.initial_settlement = Some(
                self.native
                    .as_mut()
                    .ok_or(Error::Service)?
                    .settle_initial_once_v2()
                    .map_err(Into::into),
            );
        }
        if self.require_initial_v1().is_ok() {
            Ok(())
        } else {
            let _owed = self.finish_posts_once_v1(stream);
            Err(Error::Service)
        }
    }

    pub(in crate::normal_root) fn require_initial_v1(&self) -> Result<(), Error> {
        if self.closed.is_some()
            || !matches!(self.initial_settlement, Some(Ok(())))
            || self.primary_failure_v1().is_some()
        {
            return Err(Error::Service);
        }
        self.native
            .as_ref()
            .ok_or(Error::Service)?
            .require_initial_v2()
            .map_err(Into::into)
    }

    pub(in crate::normal_root) fn peer_v1(
        &self,
    ) -> Result<&RootSelectedControllerPeerOriginalV1<'startup>, Error> {
        self.require_initial_v1()?;
        self.native
            .as_ref()
            .ok_or(Error::Service)?
            .native_peer_v2()
            .map_err(Into::into)
    }

    pub(in crate::normal_root) fn stage_receiving_v2(
        &mut self,
    ) -> Result<RootExecutionNoApplyStageReceivingV2<'_, 'startup>, Error> {
        self.require_initial_v1()?;
        Ok(RootExecutionNoApplyStageReceivingV2::new_v2(
            self.startup,
            self.native.as_mut().ok_or(Error::Service)?,
        ))
    }

    pub(in crate::normal_root) fn finish_posts_once_v1(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), Error> {
        if !self.entered || self.final_before.is_some() {
            self.complete = false;
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.final_before = Some((|| {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = receiving
                .original_mut_v1()
                .begin_native_no_apply_final_post_v2(self.native.as_mut().ok_or(Error::Service)?);
            receiving.finish_returned_v1(returned)
        })());
        // This prearmed current sample remains reached after protocol refusal.
        if matches!(self.initial_settlement, Some(Ok(()))) {
            let native = self.native.as_mut().ok_or(Error::Service)?;
            self.final_current = Some(
                native
                    .observe_final_current_once_v2(stream)
                    .map_err(Into::into),
            );
        }
        self.final_after = Some((|| {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = receiving
                .original_mut_v1()
                .finish_native_no_apply_final_post_v2(self.native.as_mut().ok_or(Error::Service)?);
            receiving.finish_returned_v1(returned)
        })());
        if self.failure().is_none() && matches!(self.final_current, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    pub(in crate::normal_root) fn settle_positive_once_v1(&mut self) -> Result<(), Error> {
        if self.complete
            || self.failure().is_some()
            || !matches!(self.final_current, Some(Ok(())))
            || !matches!(self.final_after, Some(Ok(())))
        {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.final_settlement = Some(
            self.native
                .as_mut()
                .ok_or(Error::Service)?
                .settle_final_once_v2()
                .map_err(Into::into),
        );
        self.complete = matches!(self.final_settlement, Some(Ok(()))) && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    pub(crate) fn require_completed_for_root_disposal_v1(
        &self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        if !std::ptr::eq(self.startup, startup) || !self.complete || self.failure().is_some() {
            return Err(Error::Service);
        }
        self.native
            .as_ref()
            .ok_or(Error::Service)?
            .require_completed_v2()
            .map_err(Into::into)
    }

    pub(in crate::normal_root) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        let native = self.native.as_ref()?;
        if !native
            .failure_v2()
            .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
        {
            return None;
        }
        let (peer, sample) = native.property_failure_originals_v2();
        peer.and_then(|peer| peer.property_failure_view_v1())
            .or_else(|| sample.and_then(|sample| sample.property_failure_view_v1()))
    }

    pub(in crate::normal_root) fn primary_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        error(&self.transport_shape)
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(NativePeer::capture_failure_v2)
            })
            .or_else(|| error(&self.preparation))
            .or_else(|| error(&self.capture))
            .or_else(|| self.native.as_ref()?.primary_failure_v2())
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.initial_settlement))
    }

    pub(in crate::normal_root) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.primary_failure_v1()
            .or_else(|| self.native.as_ref()?.continuation_failure_v2())
            .or_else(|| self.native.as_ref()?.post_failure_v2(Post::FinalBefore))
            .or_else(|| error(&self.final_before))
            .or_else(|| self.native.as_ref()?.current_failure_v2())
            .or_else(|| error(&self.final_current))
            .or_else(|| self.native.as_ref()?.post_failure_v2(Post::FinalAfter))
            .or_else(|| error(&self.final_after))
            .or_else(|| self.native.as_ref()?.final_settlement_failure_v2())
            .or_else(|| error(&self.final_settlement))
            .or_else(|| self.native.as_ref()?.failure_v2())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Drop for RootExecutionNoApplyControllerPeerReceivingV2<'_> {
    fn drop(&mut self) {
        if self.entered && !self.complete {
            std::process::abort();
        }
    }
}

fn error<T, E: StdError + 'static>(
    value: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
