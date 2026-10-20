//! Selects one fixed Start resource recipe after its canonical subject is read.

use crate::journal::JournalError;
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, hello_message::BrokerMethod};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::policy_compiler) enum ResourceKindV2 {
    Network,
    StorageGuestRoot,
    Mount,
    Host,
}

impl ResourceKindV2 {
    pub(super) fn from_purpose_v2(
        purpose: HostResourcePurposeDataV1,
    ) -> Result<Self, JournalError> {
        match purpose {
            HostResourcePurposeDataV1::NetworkPrepare => Ok(Self::Network),
            HostResourcePurposeDataV1::StorageGuestRoot => Ok(Self::StorageGuestRoot),
            HostResourcePurposeDataV1::MountNamespace => Ok(Self::Mount),
            // The server constructor lifts this final purpose only with its
            // complete paired-plan, protected-publication and signed Ready path.
            HostResourcePurposeDataV1::HostLaunch => Ok(Self::Host),
        }
    }

    pub(super) fn purpose_v2(self) -> HostResourcePurposeDataV1 {
        match self {
            Self::Host => HostResourcePurposeDataV1::HostLaunch,
            Self::Network => HostResourcePurposeDataV1::NetworkPrepare,
            Self::Mount => HostResourcePurposeDataV1::MountNamespace,
            Self::StorageGuestRoot => HostResourcePurposeDataV1::StorageGuestRoot,
        }
    }

    pub(in crate::policy_compiler) fn protocol_v2(self) -> BrokerSessionProtocolV1 {
        match self {
            Self::Host => BrokerSessionProtocolV1::Host,
            Self::Network => BrokerSessionProtocolV1::Network,
            Self::Mount => BrokerSessionProtocolV1::Mount,
            Self::StorageGuestRoot => BrokerSessionProtocolV1::Storage,
        }
    }

    pub(super) fn resource_method_v2(self) -> BrokerMethod {
        match self {
            Self::Host => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2,
            Self::Mount => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            Self::StorageGuestRoot => BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
        }
    }

    pub(in crate::policy_compiler) fn inventory_method_v2(self) -> BrokerMethod {
        match self {
            Self::Host => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            Self::Mount => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            Self::StorageGuestRoot => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_subject_selects_only_its_fixed_resource_recipe() {
        for kind in [ResourceKindV2::Network, ResourceKindV2::StorageGuestRoot, ResourceKindV2::Mount, ResourceKindV2::Host] {
            assert_eq!(
                ResourceKindV2::from_purpose_v2(kind.purpose_v2()).unwrap(),
                kind
            );
        }
        assert_eq!(ResourceKindV2::Host.resource_method_v2(), BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME);
        assert_eq!(ResourceKindV2::Host.inventory_method_v2(), BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME);
        assert_eq!(ResourceKindV2::StorageGuestRoot.protocol_v2(), BrokerSessionProtocolV1::Storage);
        assert_eq!(ResourceKindV2::StorageGuestRoot.resource_method_v2(),
            BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT);
        assert_eq!(ResourceKindV2::StorageGuestRoot.inventory_method_v2(),
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES);
        assert_ne!(
            ResourceKindV2::Network.resource_method_v2(),
            ResourceKindV2::Mount.resource_method_v2()
        );
        assert_ne!(
            ResourceKindV2::Network.inventory_method_v2(),
            ResourceKindV2::Mount.inventory_method_v2()
        );
    }
}
