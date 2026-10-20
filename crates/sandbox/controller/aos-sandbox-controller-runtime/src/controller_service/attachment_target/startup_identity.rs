//! Adapts the same shared lower Host/Mount identity receiving engine.
//!
//! The installed Runtime supplies prepay and retains this original facade in
//! its Parent; Broker owns the one native mechanism also used by Publisher.

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;

use super::ControllerServiceIdentityErrorV1;

pub(in crate::controller_service) struct ControllerAttachmentStartupV1 {
    original: aos_sandbox_broker::fixed_service_identity::ControllerAttachmentStartupV1,
}

impl ControllerAttachmentStartupV1 {
    pub(in crate::controller_service) fn host() -> Self {
        Self { original: aos_sandbox_broker::fixed_service_identity::ControllerAttachmentStartupV1::host() }
    }

    pub(in crate::controller_service) fn mount() -> Self {
        Self { original: aos_sandbox_broker::fixed_service_identity::ControllerAttachmentStartupV1::mount() }
    }

    pub(in crate::controller_service) async fn observe_once(
        &mut self,
    ) -> Result<(), ControllerServiceIdentityErrorV1> {
        self.original.observe_once().await
            .map_err(|()| ControllerServiceIdentityErrorV1::Changed)
    }

    pub(in crate::controller_service) fn native_temporaries_disposed_v1(&self) -> bool {
        self.original.native_temporaries_disposed_v1()
    }

    pub(in crate::controller_service) fn take_cgroup(&mut self) -> Option<RetainedCgroupAnchor> {
        self.original.take_cgroup()
    }
}
