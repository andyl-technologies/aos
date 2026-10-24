//! Challenges the genuine signed archive without granting a signing capability.
//!
//! Missing/corrupt/codec/owner variants exercise the actual archive loader and
//! its MAC boundary. They do not impersonate validly signed foreign state.
//! The exact original index stays owned throughout each filesystem mutation.

use super::*;
use crucible_engine::node_state::{NativeArchiveRecord, StateError};
use std::{fs, io::Read};

pub(super) struct DamagedArchive {
    pub(super) path: PathBuf,
    pub(super) original_index: Vec<u8>,
    pub(super) challenges: Vec<Vec<u8>>,
    pub(super) failures: Vec<StateError>,
    pub(super) manifest_challenges: Vec<InputPayload>,
    pub(super) unexpected_manifest: Option<Box<crucible_engine::node_state::VerifiedCapture>>,
    pub(super) unexpected: Vec<NativeArchiveRecord>,
    pub(super) restored: Option<NativeArchiveRecord>,
    pub(super) report: Option<InputPayload>,
    pub(super) attempted: bool,
    pub(super) complete: bool,
}

impl DamagedArchive {
    pub(super) fn new(path: PathBuf) -> Result<Self, NodeObservedError> {
        let mut challenges = Vec::new();
        let mut failures = Vec::new();
        let mut unexpected = Vec::new();
        challenges
            .try_reserve_exact(3)
            .map_err(|_| refused("Clock archive challenge slots"))?;
        failures
            .try_reserve_exact(7)
            .map_err(|_| refused("Clock archive refusal slots"))?;
        unexpected
            .try_reserve_exact(4)
            .map_err(|_| refused("Clock archive unexpected result slots"))?;
        Ok(Self {
            path,
            original_index: Vec::new(),
            challenges,
            failures,
            manifest_challenges: Vec::with_capacity(3),
            unexpected_manifest: None,
            unexpected,
            restored: None,
            report: None,
            attempted: false,
            complete: false,
        })
    }

    pub(super) fn execute(
        &mut self,
        state: &OriginalClockStateProgramme,
        original: &OriginalClockQualificationRun,
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        original.current()?;
        if self.attempted || !state.compared_data() || !state.reopened || original.runtime.is_some()
        {
            return Err(refused("Clock damaged-archive frontier unavailable"));
        }
        self.attempted = true;
        let artifact = state
            .artifact
            .as_ref()
            .ok_or_else(|| refused("Clock signed artifact absent"))?;
        let index = self
            .path
            .join(format!("{}.native-index-v1", artifact.hash.digest));
        let held = self.path.join(format!(
            "{}.normal-clock-held-index-v1",
            artifact.hash.digest
        ));
        let maximum = state_programme::limits().state.maximum_record_bytes;
        // Both the original bytes and three independently retained challenges
        // are actual owners. The same process AS/project guards bound this work.
        fs::File::open(&index)
            .map_err(super::super::super::native)?
            .take(maximum as u64 + 1)
            .read_to_end(&mut self.original_index)
            .map_err(super::super::super::native)?;
        if self.original_index.is_empty() || self.original_index.len() > maximum {
            return Err(refused("Clock actual signed index extent"));
        }
        aggregate
            .authenticate_current()
            .map_err(super::super::super::native)?;
        let original_value = canonical::parse_json(&self.original_index, maximum)?;
        for pointer in [
            "/authentication/0",
            "/body/owners/0/key/schema/id",
            "/body/owners/0/owner",
        ] {
            aggregate
                .authenticate_current()
                .map_err(super::super::super::native)?;
            let mut changed = original_value.clone();
            let leaf = changed
                .pointer_mut(pointer)
                .ok_or_else(|| refused("Clock actual index grammar changed"))?;
            if pointer == "/authentication/0" {
                let byte = leaf
                    .as_u64()
                    .filter(|byte| *byte <= 255)
                    .ok_or_else(|| refused("Clock actual authentication byte changed"))?;
                *leaf = serde_json::json!((byte + 1) % 256);
            } else {
                *leaf = serde_json::json!("normal-clock/foreign-challenge");
            }
            let bytes = canonical::canonical_json(&changed)?;
            if bytes.len() > maximum {
                return Err(refused("Clock challenge index ceiling"));
            }
            self.challenges.push(bytes);
        }
        // Save by exclusive rename; no key is copied, no valid signature minted,
        // and no independent mutable world is staged for any challenge.
        if held.exists() {
            return Err(refused("Clock held original archive already exists"));
        }
        aggregate
            .authenticate_current()
            .map_err(super::super::super::native)?;
        fs::rename(&index, &held).map_err(super::super::super::native)?;
        self.refusal(state, artifact)?;
        fs::rename(&held, &index).map_err(super::super::super::native)?;
        self.restored = Some(
            state
                .archive
                .load(artifact)
                .map_err(super::super::super::native)?,
        );
        for ordinal in 0..self.challenges.len() {
            aggregate
                .authenticate_current()
                .map_err(super::super::super::native)?;
            fs::rename(&index, &held).map_err(super::super::super::native)?;
            // On a refused write/load/unwind the pristine file remains at held;
            // the same retained programme is poisoned rather than retried.
            fs::write(&index, &self.challenges[ordinal]).map_err(super::super::super::native)?;
            self.refusal(state, artifact)?;
            fs::remove_file(&index).map_err(super::super::super::native)?;
            fs::rename(&held, &index).map_err(super::super::super::native)?;
            self.restored = Some(
                state
                    .archive
                    .load(artifact)
                    .map_err(super::super::super::native)?,
            );
        }
        self.challenge_manifests(state, original, aggregate)?;
        self.authenticate(state, original)?;
        self.report = Some(report(&(
            "crucible.original-clock-signed-archive-refusals/1",
            artifact,
            [
                "missing-index",
                "corrupt-authentication",
                "changed-codec-under-original-seal",
                "changed-owner-under-original-seal",
            ],
            self.failures
                .iter()
                .map(|error| (&error.component, &error.reason))
                .collect::<Vec<_>>(),
            "signed loader refusals plus exact native-schema/world/owner admission refusals before dependency or proof callbacks; pristine signed original still admitted; no validly-signed foreign-state claim",
        ))?);
        self.complete = true;
        Ok(())
    }

    fn challenge_manifests(
        &mut self,
        state: &OriginalClockStateProgramme,
        original: &OriginalClockQualificationRun,
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        use crucible_engine::node_state::{StateErrorCode, admit_capture};
        let captured = state
            .record
            .as_ref()
            .ok_or_else(|| refused("Clock captured manifest absent"))?;
        for ordinal in 0..3 {
            aggregate
                .authenticate_current()
                .map_err(super::super::super::native)?;
            let mut changed = captured.manifest().clone();
            let (code, component) = match ordinal {
                0 => {
                    changed.owners[0].state_schema.id =
                        Id::new("normal-clock/unsupported-native-codec")?;
                    (StateErrorCode::Incompatible, original.node.as_str())
                }
                1 => {
                    changed.scenario_ref =
                        canonical::content_ref(b"foreign-source", "application/json")?;
                    (StateErrorCode::Incompatible, "world")
                }
                _ => {
                    changed.owners[0].state_domain_ids =
                        vec![Id::new("normal-clock/foreign-domain")?];
                    (
                        StateErrorCode::IncompleteClosure,
                        captured.manifest().owners[0].capture_owner_id.as_str(),
                    )
                }
            };
            let bytes = canonical::canonical_json(&serde_json::to_value(&changed)?)?;
            if bytes.len() > state_programme::limits().state.maximum_record_bytes {
                return Err(refused("Clock manifest challenge byte ceiling"));
            }
            self.manifest_challenges.push(InputPayload {
                reference: canonical::content_ref(&bytes, "application/json")?,
                bytes,
            });
            let candidate = &self.manifest_challenges[ordinal];
            let evidence = ManifestChallenge {
                candidate,
                later_phase: std::cell::Cell::new(false),
            };
            // This is the actual public restoration validator over the same
            // genuine graph. No successful native provenance is implemented by
            // this content-only challenge; it must reject the selected field
            // before closure/proof work, or the experiment itself fails.
            match admit_capture(
                &original.graph,
                &candidate.reference,
                state_programme::requirements()?,
                &evidence,
                state_programme::limits().state,
            ) {
                Err(error) => {
                    let matched = error.code == code
                        && error.component == component
                        && !evidence.later_phase.get();
                    self.failures.push(error);
                    if !matched {
                        return Err(refused(
                            "Clock manifest refused outside its expected pre-staging guard",
                        ));
                    }
                }
                Ok(unexpected) => {
                    self.unexpected_manifest = Some(Box::new(unexpected));
                    return Err(refused("changed Clock manifest unexpectedly admitted"));
                }
            }
        }
        Ok(())
    }

    fn refusal(
        &mut self,
        state: &OriginalClockStateProgramme,
        artifact: &ContentRef,
    ) -> Result<(), NodeObservedError> {
        match state.archive.load(artifact) {
            Err(original) => {
                let matched = if self.failures.is_empty() {
                    original.code == crucible_engine::node_state::StateErrorCode::Content
                        && original.component == "native archive storage"
                } else {
                    original.code == crucible_engine::node_state::StateErrorCode::NativeEvidence
                        && original.component == "native archive"
                        && original.reason == "native archive authentication failed"
                };
                self.failures.push(original);
                if !matched {
                    return Err(refused(
                        "Clock signed archive refused outside the challenged guard",
                    ));
                }
            }
            Ok(original) => {
                self.unexpected.push(original);
                return Err(refused("damaged Clock signed archive unexpectedly loaded"));
            }
        }
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        state: &OriginalClockStateProgramme,
        original: &OriginalClockQualificationRun,
    ) -> Result<(), NodeObservedError> {
        original.current()?;
        if !self.attempted
            || self.failures.len() != 7
            || self.manifest_challenges.len() != 3
            || self.unexpected_manifest.is_some()
            || self.challenges.len() != 3
            || !self.unexpected.is_empty()
            || !state.compared_data()
            || original.runtime.is_some()
        {
            return Err(refused(
                "Clock damaged-archive original population incomplete",
            ));
        }
        let artifact = state
            .artifact
            .as_ref()
            .ok_or_else(|| refused("Clock original archive identity absent"))?;
        let retired_capture = original
            .captured
            .as_ref()
            .ok_or_else(|| refused("Clock retired original capture absent"))?;
        if retired_capture.artifact() != artifact
            || retired_capture.manifest()
                != state
                    .record
                    .as_ref()
                    .ok_or_else(|| refused("Clock source record absent"))?
                    .manifest()
            || original.retired.is_none()
        {
            return Err(refused(
                "Clock archive challenge names another retired original",
            ));
        }
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| refused("Clock original restored index absent"))?;
        let captured = state
            .record
            .as_ref()
            .ok_or_else(|| refused("Clock original capture owner absent"))?;
        let loaded = state
            .archive
            .load(artifact)
            .map_err(super::super::super::native)?;
        if restored.artifact() != artifact
            || loaded.manifest() != captured.manifest()
            || loaded.owners() != captured.owners()
        {
            return Err(refused(
                "Clock pristine archive failed exact reauthentication",
            ));
        }
        let factory = state.branches[0]
            .factory
            .as_ref()
            .ok_or_else(|| refused("Clock actual native factory absent"))?;
        // The unchanged original still passes real source/native admission.
        loaded
            .admit(
                &original.graph,
                state_programme::requirements()?,
                factory.as_ref(),
            )
            .map_err(super::super::super::native)?;
        Ok(())
    }
}

// Supplies only the malformed manifest bytes to the ordinary validator. This
// content lookup has no native proof, source selector, model or staging owner.
struct ManifestChallenge<'a> {
    candidate: &'a InputPayload,
    later_phase: std::cell::Cell<bool>,
}

impl crucible_engine::node_state::CaptureEvidence for ManifestChallenge<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        if reference != &self.candidate.reference || self.candidate.bytes.len() > maximum {
            self.later_phase.set(true);
            return Err(state::state_error(
                "Clock challenge requested other content",
            ));
        }
        reference
            .verify(&self.candidate.bytes)
            .map_err(state::state_error)?;
        Ok(self.candidate.bytes.clone())
    }

    fn dependencies(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.later_phase.set(true);
        Err(state::state_error("Clock challenge reached closure work"))
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_format::CaptureManifest,
        _: &crucible_node_format::CapturedOwner,
        _: &crucible_engine::node_state::StateRequirements,
        _: &crucible_engine::node_state::VerifiedStateContent,
    ) -> Result<crucible_engine::node_state::NativeOwnerCaptureProof, StateError> {
        self.later_phase.set(true);
        Err(state::state_error(
            "Clock challenge cannot supply native provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_format::CaptureManifest,
        _: &crucible_engine::node_state::VerifiedStateContent,
    ) -> Result<crucible_engine::node_state::NativeCoordinatorCaptureProof, StateError> {
        self.later_phase.set(true);
        Err(state::state_error(
            "Clock challenge cannot supply coordinator provenance",
        ))
    }
}
