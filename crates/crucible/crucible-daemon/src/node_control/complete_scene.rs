//! Selects only the locally installed collecting scene in control edition twelve.
//!
//! ```json
//! {"format":"crucible.node-control","version":12,"request_id":"operator/collect",
//!  "command":{"operation":"complete_scene_prepare"}}
//! ```
//!
//! The request carries no paths, manifest, resource revision or class claim.
//! Installation happens independently before the private endpoint is published.

use super::*;

impl NodeControlRequest {
    /// Requests the installed scene's once-only inactive collecting preparation.
    ///
    /// # Errors
    /// Refuses an invalid correlation identity. Dispatch separately refuses a
    /// missing, spent or unqualified actual installed source/lifecycle gate.
    pub fn complete_scene_prepare(request_id: &str) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 12,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::CompleteScenePrepare {},
        };
        request.validate()?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collecting_edition_has_no_caller_authority_and_preserves_status_bytes() {
        let request = NodeControlRequest::complete_scene_prepare("operator/collect").unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["version"], 12);
        assert_eq!(
            value["command"],
            serde_json::json!({"operation":"complete_scene_prepare"})
        );
        let mut old_edition = request.clone();
        old_edition.version = 1;
        assert!(old_edition.validate().is_err());
        let mut forged = value;
        forged["command"]["accepted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NodeControlRequest>(forged).is_err());

        let old = NodeControlRequest::new(
            "operator/status",
            NodeControlCommand::Status {
                execution: "00112233445566778899aabbccddeeff".into(),
            },
        )
        .unwrap();
        assert_eq!(canonical::canonical_json(&serde_json::to_value(old).unwrap()).unwrap(),
            br#"{"command":{"execution":"00112233445566778899aabbccddeeff","operation":"status"},"format":"crucible.node-control","request_id":"operator/status","version":1}"#);
    }
}
