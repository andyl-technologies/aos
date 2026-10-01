//! Bounded isolated qualification controls and retained queue observation records.
//!
//! ```text
//! start -> begin(object) -> grant(parts) -> report(parts) -> close(object)
//! close -> actual verification queue -> retained proof -> authenticated status
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};

pub(crate) const PATH: &str = "/_internal/storage/direct-upload-qualification";
pub(crate) const HEADER: &str = "x-aos-direct-qualification-signature";
pub(crate) const REQUEST_DOMAIN: &[u8] = b"aos.direct-upload.qualification-request.v1\0";
pub(crate) const REPLY_DOMAIN: &[u8] = b"aos.direct-upload.qualification-reply.v1\0";
pub(crate) const QUEUE_DOMAIN: &[u8] = b"aos.direct-upload.qualification-queue.v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Control {
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) nonce: String,
    pub(crate) source_digest: String,
    pub(crate) script_version: String,
    pub(crate) expires_at: WireInteger,
    pub(crate) action: Action,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Action {
    Start {
        provider: Provider,
        objects: Vec<ObjectPlan>,
    },
    Begin {
        object_id: String,
    },
    Grant {
        object_id: String,
        parts: Vec<DirectPart>,
    },
    Report {
        object_id: String,
        reports: Vec<DirectPartReport>,
    },
    Close {
        object_id: String,
        #[serde(default)]
        defer_enqueue: bool,
    },
    Enqueue {
        object_ids: Vec<String>,
    },
    Status,
    Inspect {
        object_id: String,
        after_attempt: u32,
    },
    Clock,
    ExpiredMutation {
        cutoff: WireInteger,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Provider {
    Managed,
    External {
        selector: DirectExternalProfileSelector,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObjectPlan {
    pub(crate) object_id: String,
    pub(crate) byte_size: WireInteger,
    pub(crate) expected_sha256: String,
    pub(crate) part_size: WireInteger,
    pub(crate) metadata: bool,
}

impl Control {
    pub(crate) fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && valid_direct_digest(&self.run_id)
                && valid_direct_digest(&self.nonce)
                && valid_direct_digest(&self.source_digest)
                && valid_direct_identity(&self.script_version)
                && now < self.expires_at.get()
                && self.expires_at.get() <= now.saturating_add(30),
            "isolated qualification control invalid"
        );
        match &self.action {
            Action::Start { provider, objects } => {
                if let Provider::External { selector } = provider {
                    selector.validate()?;
                }
                ensure!(
                    !objects.is_empty() && objects.len() <= 32,
                    "qualification object count invalid"
                );
                let mut ids = std::collections::BTreeSet::new();
                for object in objects {
                    ensure!(
                        valid_direct_digest(&object.object_id)
                            && valid_direct_digest(&object.expected_sha256)
                            && object.byte_size.get() > 0
                            && (!object.metadata
                                || object.byte_size.get()
                                    <= aos_hub_core::fetch::MAX_CACHE_NARINFO_BYTES as u64)
                            && ids.insert(&object.object_id),
                        "qualification object invalid"
                    );
                }
            }
            Action::Begin { object_id }
            | Action::Close { object_id, .. }
            | Action::Inspect { object_id, .. } => {
                ensure!(
                    valid_direct_digest(object_id),
                    "qualification object identity invalid"
                );
            }
            Action::Enqueue { object_ids } => {
                ensure!(
                    !object_ids.is_empty()
                        && object_ids.len() <= 32
                        && object_ids.iter().all(|id| valid_direct_digest(id)),
                    "qualification enqueue batch invalid"
                );
            }
            Action::Grant { object_id, parts } => {
                ensure!(
                    valid_direct_digest(object_id) && !parts.is_empty() && parts.len() <= 32,
                    "qualification part batch invalid"
                );
            }
            Action::Report { object_id, reports } => {
                ensure!(
                    valid_direct_digest(object_id) && !reports.is_empty() && reports.len() <= 32,
                    "qualification report batch invalid"
                );
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Original {
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) source_digest: String,
    pub(crate) script_version: String,
    pub(crate) deployment_id: String,
    pub(crate) public_origin: String,
    pub(crate) execution_kind: DirectWorkerExecutionKind,
    pub(crate) provider: Provider,
    pub(crate) objects: Vec<ObjectPlan>,
    pub(crate) limits: DirectWorkerQualificationLimits,
    pub(crate) maximum_parallel_objects: WireInteger,
    pub(crate) bulk_queue_name: String,
    pub(crate) metadata_queue_name: String,
    pub(crate) bulk_queue_policy: DirectQueueDeliveryPolicy,
    pub(crate) metadata_queue_policy: DirectQueueDeliveryPolicy,
    pub(crate) material: super::fixture::Material,
    pub(crate) admission_expires_at: WireInteger,
    pub(crate) created_at_millis: WireInteger,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_expired_controls_and_unknown_actions() {
        let value = serde_json::json!({"version":1,"runId":"aa".repeat(32),
            "nonce":"bb".repeat(32),"sourceDigest":"cc".repeat(32),
            "scriptVersion":"script-1","expiresAt":"100","action":{"kind":"clock"}});
        let control: Control = serde_json::from_value(value.clone()).unwrap();
        assert!(control.validate(99).is_ok());
        assert!(control.validate(100).is_err());
        let mut unknown = value;
        unknown["action"]["kind"] = "promote".into();
        assert!(serde_json::from_value::<Control>(unknown).is_err());
    }

    #[test]
    fn rejects_metadata_above_the_actual_parser_bound_before_admission() {
        let mut control = Control {
            version: 1,
            run_id: "aa".repeat(32),
            nonce: "bb".repeat(32),
            source_digest: "cc".repeat(32),
            script_version: "script-1".into(),
            expires_at: WireInteger::new(100),
            action: Action::Start {
                provider: Provider::Managed,
                objects: vec![ObjectPlan {
                    object_id: "dd".repeat(32),
                    expected_sha256: "ee".repeat(32),
                    byte_size: WireInteger::new(
                        aos_hub_core::fetch::MAX_CACHE_NARINFO_BYTES as u64,
                    ),
                    part_size: WireInteger::new(8 * 1024 * 1024),
                    metadata: true,
                }],
            },
        };
        assert!(control.validate(99).is_ok());
        if let Action::Start { objects, .. } = &mut control.action {
            objects[0].byte_size =
                WireInteger::new(aos_hub_core::fetch::MAX_CACHE_NARINFO_BYTES as u64 + 1);
        }
        assert!(control.validate(99).is_err());
    }
}
