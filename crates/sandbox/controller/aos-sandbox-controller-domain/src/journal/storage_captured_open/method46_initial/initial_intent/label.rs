//! Retains raw labels of the actual fixed initial-intent file descriptions.
//!
//! A pathname transition cannot exclude a foreign-label inode renamed into the
//! same directory. The genuine startup selects one closed role before quoting;
//! each opened intent and writable stage must carry that role's exact label.

use std::fs::File;

use super::Method46InitialServiceRoleV1;

pub(super) const LABEL_BYTES: usize = 256;

#[derive(Clone, Copy)]
pub(super) enum IntentContext {
    Controller,
    Storage,
    // These tests exercise generic native durability on an unconfined host.
    // No production constructor or genuine Source can select this variant.
    #[cfg(test)]
    NativeDurabilityFixture,
}

impl From<Method46InitialServiceRoleV1> for IntentContext {
    fn from(role: Method46InitialServiceRoleV1) -> Self {
        match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => Self::Controller,
            Method46InitialServiceRoleV1::StorageBroker => Self::Storage,
        }
    }
}

impl IntentContext {
    fn matches(self, observed: &[u8]) -> bool {
        match self {
            Self::Controller => {
                observed == b"system_u:object_r:aos_method46_controller_initial_intent_t"
            }
            Self::Storage => observed == b"system_u:object_r:aos_method46_storage_initial_intent_t",
            #[cfg(test)]
            Self::NativeDurabilityFixture => true,
        }
    }
}

pub(super) struct IntentLabelOriginal {
    result: Option<rustix::io::Result<usize>>,
    bytes: [u8; LABEL_BYTES],
}

impl IntentLabelOriginal {
    pub(super) fn new() -> Self {
        Self {
            result: None,
            bytes: [0; LABEL_BYTES],
        }
    }

    pub(super) fn observe(&mut self, file: &File) {
        if self.result.is_none() {
            self.result = Some(rustix::fs::fgetxattr(
                file,
                "security.selinux",
                &mut self.bytes,
            ));
        }
    }

    pub(super) fn require(&self, context: IntentContext) -> bool {
        #[cfg(test)]
        if matches!(context, IntentContext::NativeDurabilityFixture) {
            return self.result.is_some();
        }

        let Some(Ok(length)) = self.result else {
            return false;
        };
        let Some(observed) = self.bytes.get(..length) else {
            return false;
        };
        context.matches(observed.strip_suffix(b"\0").unwrap_or(observed))
    }

    pub(super) fn failure(&self) -> Option<&rustix::io::Errno> {
        self.result.as_ref()?.as_ref().err()
    }

    #[cfg(test)]
    pub(super) fn result_observed(&self) -> bool {
        self.result.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_own_intent_label_is_accepted() {
        for (context, expected) in [
            (
                IntentContext::Controller,
                b"system_u:object_r:aos_method46_controller_initial_intent_t".as_slice(),
            ),
            (
                IntentContext::Storage,
                b"system_u:object_r:aos_method46_storage_initial_intent_t".as_slice(),
            ),
        ] {
            let mut original = IntentLabelOriginal::new();
            assert!(!original.require(context));
            original.result = Some(Err(rustix::io::Errno::NODATA));
            assert!(!original.require(context));
            assert_eq!(original.failure(), Some(&rustix::io::Errno::NODATA));

            for suffix in [b"".as_slice(), b"\0"] {
                original.bytes.fill(0);
                original.bytes[..expected.len()].copy_from_slice(expected);
                original.bytes[expected.len()..expected.len() + suffix.len()]
                    .copy_from_slice(suffix);
                original.result = Some(Ok(expected.len() + suffix.len()));
                assert!(original.require(context));
            }

            for foreign in [
                b"system_u:object_r:aos_method46_controller_floor_t".as_slice(),
                b"system_u:object_r:aos_method46_storage_floor_t",
                b"system_u:object_r:aos_method46_controller_main_t",
                b"system_u:object_r:aos_method46_storage_main_t",
                b"system_u:object_r:aos_method46_controller_initial_intent_t:s0",
                b"system_u:object_r:aos_method46_storage_initial_intent_t:s0",
            ] {
                original.bytes.fill(0);
                original.bytes[..foreign.len()].copy_from_slice(foreign);
                original.result = Some(Ok(foreign.len()));
                assert!(!original.require(context));
            }
            original.result = Some(Ok(LABEL_BYTES + 1));
            assert!(!original.require(context));
        }

        assert!(
            !IntentContext::Controller
                .matches(b"system_u:object_r:aos_method46_storage_initial_intent_t")
        );
        assert!(
            !IntentContext::Storage
                .matches(b"system_u:object_r:aos_method46_controller_initial_intent_t")
        );
    }
}
