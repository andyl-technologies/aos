//! Serializes original partial failure observations without transferring custody.
//!
//! The owning actor retains peers, runtime journals and its immutable original
//! population. Unavailable inert copies remain explicitly incomplete; this
//! helper neither retries effects nor substitutes missing native evidence.
//!
//! ```json
//! {"schema":"crucible.reference.candidate-failure.v1","qualification_accepted":false}
//! ```

use crucible_node_provider::client::ObservationLimits;

use super::super::source_original_conflict_plan::MAXIMUM_ARCHIVE_BYTES;
use super::Actor;

impl Actor {
    pub(super) fn failed_original(&self, error: &str) -> serde_json::Value {
        let observations=self.observers.iter().map(|slot| {
            let slot=slot.borrow();
            let Some(observer)=slot.as_ref() else {
                return serde_json::json!({"recording_complete":false,"reason":"native observer not reached"});
            };
            let snapshot=(|| {
                let keys=observer.request_keys()?;
                let refs=observer.content_references()?;
                observer.snapshot(&keys,&refs,ObservationLimits {
                    maximum_requests:1024,maximum_objects:1024,maximum_bytes:8*1024*1024,
                })
            })();
            match snapshot {
                Ok(snapshot)=>serde_json::to_value(snapshot).unwrap_or_else(|_|serde_json::json!({"recording_complete":false,"reason":"original observation encoding refused"})),
                Err(_)=>serde_json::json!({"recording_complete":false,"reason":"original observation unavailable"}),
            }
        }).collect::<Vec<_>>();
        let transmission_observations = self.transmission_observers.iter().map(|slot| {
            let slot = slot.borrow();
            let Some(observer) = slot.as_ref() else {
                return serde_json::json!({"incomplete": true, "reason": "wire observation not reached"});
            };
            match observer.snapshot(1024 * 1024) {
                Ok(snapshot) => serde_json::to_value(snapshot).unwrap_or_else(|_| {
                    serde_json::json!({"incomplete": true, "reason": "original wire observation encoding refused"})
                }),
                Err(_) => serde_json::json!({"incomplete": true, "reason": "original wire observation unavailable"}),
            }
        }).collect::<Vec<_>>();
        let conflict_observations = self.conflict_observers.iter().map(|slot| {
            let slot = slot.borrow();
            let Some(observer) = slot.as_ref() else { return serde_json::json!({"incomplete":true,"reason":"conflict observer not reached"}); };
            match observer.snapshot(MAXIMUM_ARCHIVE_BYTES) {
                Ok(snapshot) => serde_json::to_value(snapshot).unwrap_or_else(|_| serde_json::json!({"incomplete":true,"reason":"conflict snapshot encoding refused"})),
                Err(_) => serde_json::json!({"incomplete":true,"reason":"conflict snapshot unavailable"}),
            }
        }).collect::<Vec<_>>();
        let candidate=self.candidate.as_ref().map(|candidate| serde_json::json!({
            "world":candidate.definition.world,
            "activation":crucible::node_contract::SavedRuntimeActivation::from(&candidate.activation),
            "predeclared_cases":self.planned.iter().map(|cases|cases.iter().map(|case|
                serde_json::json!({"stage":case.stage,"batch":case.batch,"operation":case.operation,"grant":case.grant,"input_cut":case.input_cut})
            ).collect::<Vec<_>>()).collect::<Vec<_>>(),
        }));
        serde_json::json!({"schema":"crucible.reference.candidate-failure.v1","phase":self.phase,
            "error":error,"candidate":candidate,"original_observations":observations,"original_transmission_observations":transmission_observations,"original_conflict_observations":conflict_observations,"original_conflict_premises":self.conflict_policies.iter().map(|policy|policy.retained()).collect::<Vec<_>>(),
            "original_completed_windows":self.windows,"original_runtime_retries":self.runtime_retries,"source_probes":self.probes,"prepared_probes":self.prepared_probes,"wire_resends":self.resends,"lifecycle_resend_premises":self.lifecycle_policies.iter().map(|policy|policy.retained_premises()).collect::<Vec<_>>(),"qualification_accepted":false})
    }
}
