//! Names V2 dependency relations and their exact typed endpoint grammar.
//!
//! The canonical graph producer derives these relations from its actual Source,
//! Controller and Snapshot originals. Independent Root verification must
//! recompute the full relations; endpoint typing alone is comparison DATA.
//! Historical AOSDEL01 keeps its old literal class-range decoder.

use super::{LifecycleModelError, LifecycleResourceV1};

/// Selects one explicit relation in the current canonical Delete graph.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DeleteDependencyClassDataV2 {
    /// A child Sandbox depends on its exact Source/Controller parent Sandbox.
    SandboxParent = 1,
    /// An admitted Execution depends on its exact owner Sandbox.
    ExecutionOwner = 2,
    /// An Attachment depends on its exact destination Sandbox.
    AttachmentDestination = 3,
    /// An Attachment or retained Snapshot references an actual logical View.
    LogicalView = 4,
    /// A retained Snapshot depends on its source or an actual ancestry Sandbox.
    SnapshotRetention = 5,
    /// A live View depends on the exact Sandbox that owns its Source export.
    LiveViewOwner = 6,
    /// The exact provisioning companion assignment/reservation set is retired.
    ///
    /// The surrounding V2 parser additionally requires all original companion
    /// descriptors, keys and the three exact typed companion relations.
    ProvisioningCompanion = 7,
    /// An Execution consumes an Attachment in its same Sandbox assignment epoch.
    AssignmentAttachmentConsumer = 8,
}

impl DeleteDependencyClassDataV2 {
    /// Returns the single canonical current wire code.
    #[must_use]
    pub const fn code_v2(self) -> u8 {
        self as u8
    }

    /// Checks the declared relation against both complete typed endpoints.
    ///
    /// This validates grammar only. It does not authenticate a parent, live
    /// export, manifest, current owner, companion set or protected transaction.
    ///
    /// # Errors
    /// Refuses unknown classes, cross-kind endpoints and self dependencies.
    pub fn from_endpoints_v2(
        code: u8,
        dependent: LifecycleResourceV1,
        dependency: LifecycleResourceV1,
    ) -> Result<Self, LifecycleModelError> {
        use LifecycleResourceV1 as Resource;
        if dependent == dependency {
            return Err(LifecycleModelError::InvalidModel);
        }
        match (code, dependent, dependency) {
            (1, Resource::Sandbox(_), Resource::Sandbox(_)) => Ok(Self::SandboxParent),
            (2, Resource::Execution(_), Resource::Sandbox(_)) => Ok(Self::ExecutionOwner),
            (3, Resource::Attachment(_), Resource::Sandbox(_)) => Ok(Self::AttachmentDestination),
            (4, Resource::Attachment(_) | Resource::Snapshot(_), Resource::View(_)) => Ok(Self::LogicalView),
            (5, Resource::Snapshot(_), Resource::Sandbox(_)) => Ok(Self::SnapshotRetention),
            (6, Resource::View(_), Resource::Sandbox(_)) => Ok(Self::LiveViewOwner),
            (7, Resource::Other(_), Resource::Sandbox(_) | Resource::Other(_)) => Ok(Self::ProvisioningCompanion),
            (8, Resource::Execution(_), Resource::Attachment(_)) => Ok(Self::AssignmentAttachmentConsumer),
            _ => Err(LifecycleModelError::InvalidModel),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{ExecutionId, ResourceId, SandboxId, SnapshotId, ViewId};

    #[test]
    fn relation_codes_reject_resealed_cross_kind_meanings() {
        use DeleteDependencyClassDataV2 as Class;
        use LifecycleResourceV1 as Resource;
        let sandbox = Resource::Sandbox(SandboxId::from_bytes([1; 16]));
        let child = Resource::Sandbox(SandboxId::from_bytes([2; 16]));
        let execution = Resource::Execution(ExecutionId::from_bytes([2; 16]));
        let view = Resource::View(ViewId::from_bytes([3; 16]));
        let snapshot = Resource::Snapshot(SnapshotId::from_bytes([4; 16]));
        let attachment = Resource::Attachment(ResourceId::from_bytes([5; 16]));

        assert_eq!(Class::from_endpoints_v2(1, child, sandbox).unwrap(), Class::SandboxParent);
        assert_eq!(Class::from_endpoints_v2(2, execution, sandbox).unwrap(), Class::ExecutionOwner);
        assert_eq!(Class::from_endpoints_v2(3, attachment, sandbox).unwrap(), Class::AttachmentDestination);
        assert_eq!(Class::from_endpoints_v2(4, attachment, view).unwrap(), Class::LogicalView);
        assert_eq!(Class::from_endpoints_v2(4, snapshot, view).unwrap(), Class::LogicalView);
        assert_eq!(Class::from_endpoints_v2(5, snapshot, sandbox).unwrap(), Class::SnapshotRetention);
        assert_eq!(Class::from_endpoints_v2(6, view, sandbox).unwrap(), Class::LiveViewOwner);

        assert!(Class::from_endpoints_v2(2, child, sandbox).is_err());
        assert!(Class::from_endpoints_v2(1, execution, sandbox).is_err());
        assert!(Class::from_endpoints_v2(4, view, attachment).is_err());
        assert!(Class::from_endpoints_v2(6, snapshot, sandbox).is_err());
        assert_eq!(Class::from_endpoints_v2(8, execution, attachment).unwrap(), Class::AssignmentAttachmentConsumer);
        assert!(Class::from_endpoints_v2(8, attachment, execution).is_err());
        assert!(Class::from_endpoints_v2(1, sandbox, sandbox).is_err());
        for unknown in [0, 9, 255] {
            assert!(Class::from_endpoints_v2(unknown, child, sandbox).is_err());
        }
    }
}
