//! Repository-bound durable state and rebuildable local projections.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_maintain::agent::{AgentResultV1, AgentTaskV1};
use aos_maintain::discovery::DiscoverySnapshotV1;
use aos_maintain::envelope::InventoryEnvelopeV1;
use aos_maintain::plan::PackageUpdatePlanV1;
use aos_maintain::remote::{PullRequestObservationV1, PullRequestPublicationV1};
use aos_maintain::run::{
    GateResultsV1, MaterializationRecordV1, PackageUpdateEvidenceV1, PackageUpdateRunV1,
    RepairAttemptV1,
};
use aos_maintain::workflow::{
    ActorClass, EventBindings, JournalEvent, JournalPayload, RunState, verify_journal,
};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::inventory::RepositoryCoordinates;

const MAX_STATE_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// Resolves and owns one local repository's protected maintenance paths.
pub(super) struct StateStore {
    root: PathBuf,
    repository: PathBuf,
}

/// Holds an exclusive lease for one immutable maintenance plan.
///
/// The file descriptor intentionally has no public operations: retaining this
/// value is the lease, and dropping it releases the kernel lock.
pub(super) struct OperationLease {
    _file: File,
}

/// Durable owner preimage written before deterministic materialization edits.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct MaterializationPreimage {
    pub(super) path: String,
    pub(super) mode: u32,
    pub(super) contents: String,
}

impl StateStore {
    /// Opens the repository namespace and creates protected directories.
    pub(super) fn open(
        override_root: Option<&Path>,
        coordinates: &RepositoryCoordinates,
    ) -> Result<Self> {
        Self::open_identity(
            override_root,
            &coordinates.canonical_remote,
            &coordinates.common_dir,
            false,
        )
    }

    /// Opens the namespace already bound by a validated inventory envelope.
    pub(super) fn open_for_envelope(
        override_root: Option<&Path>,
        envelope: &InventoryEnvelopeV1,
    ) -> Result<Self> {
        Self::open_identity(
            override_root,
            &envelope.canonical_remote,
            Path::new(&envelope.git_common_dir),
            true,
        )
    }

    fn open_identity(
        override_root: Option<&Path>,
        canonical_remote: &str,
        common_dir: &Path,
        create: bool,
    ) -> Result<Self> {
        let root = state_root(override_root)?;
        if create {
            secure_directory(&root)?;
        }
        let repositories = root.join("repositories");
        if create {
            secure_directory(&repositories)?;
        }

        let identity = Sha256Digest::separated(
            "aos.maintain.repository/v1",
            format!("{}\0{}", canonical_remote, common_dir.display()),
        );
        let repository = repositories.join(identity.hex());
        if create {
            secure_directory(&repository)?;
        }
        Ok(Self { root, repository })
    }

    /// Writes the latest repository-bound inventory projection atomically.
    pub(super) fn write_inventory(&self, inventory: &InventoryEnvelopeV1) -> Result<()> {
        atomic_write(&self.repository, "inventory.json", inventory)
    }

    /// Reads and validates the latest repository-bound inventory projection.
    pub(super) fn read_inventory(&self) -> Result<Option<InventoryEnvelopeV1>> {
        let Some(value) = read_optional(&self.repository.join("inventory.json"), "inventory")?
        else {
            return Ok(None);
        };
        let inventory: InventoryEnvelopeV1 = value;
        inventory.validate()?;
        Ok(Some(inventory))
    }

    /// Writes an immutable content-addressed discovery snapshot and latest pointer.
    pub(super) fn write_discovery(&self, snapshot: &DiscoverySnapshotV1) -> Result<Sha256Digest> {
        snapshot.validate()?;
        let digest = Sha256Digest::of_canonical(aos_maintain::DISCOVERY_SNAPSHOT_V1, snapshot)?;
        let snapshots = self.repository.join("discovery");
        secure_directory(&snapshots)?;
        let name = format!("{}.json", digest.hex());
        write_immutable(&snapshots, &name, snapshot)?;
        atomic_write(&self.repository, "discovery-latest.json", snapshot)?;
        Ok(digest)
    }

    /// Reads and validates the latest discovery projection, when present.
    pub(super) fn read_discovery(&self) -> Result<Option<DiscoverySnapshotV1>> {
        let Some(value) = read_optional(
            &self.repository.join("discovery-latest.json"),
            "discovery snapshot",
        )?
        else {
            return Ok(None);
        };
        let snapshot: DiscoverySnapshotV1 = value;
        snapshot.validate()?;
        Ok(Some(snapshot))
    }

    /// Stores one immutable plan beneath its deterministic plan identity.
    pub(super) fn write_plan(&self, plan: &PackageUpdatePlanV1) -> Result<Sha256Digest> {
        plan.validate()?;
        let plans = self.repository.join("plans");
        secure_directory(&plans)?;
        let name = format!("{}.json", plan.plan_id);
        write_immutable(&plans, &name, plan)?;
        Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_PLAN_V1, plan)
    }

    /// Reads an exact immutable plan identity.
    pub(super) fn read_plan(&self, plan_id: &str) -> Result<Option<PackageUpdatePlanV1>> {
        if plan_id.is_empty()
            || plan_id.len() > 96
            || !plan_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
            })
        {
            bail!("plan identity is invalid");
        }
        let Some(plan) = read_optional(
            &self
                .repository
                .join("plans")
                .join(format!("{plan_id}.json")),
            "package update plan",
        )?
        else {
            return Ok(None);
        };
        let plan: PackageUpdatePlanV1 = plan;
        plan.validate()?;
        Ok(Some(plan))
    }

    /// Resolves the controller-owned path for one run's managed worktree.
    pub(super) fn worktree_path(&self, run_id: &str) -> Result<PathBuf> {
        validate_state_name(run_id, "run")?;
        let worktrees = self.repository.join("worktrees");
        secure_directory(&worktrees)?;
        Ok(worktrees.join(run_id))
    }

    /// Creates protected run directories and stores their immutable plan copy.
    pub(super) fn initialize_run(
        &self,
        run: &PackageUpdateRunV1,
        plan: &PackageUpdatePlanV1,
    ) -> Result<()> {
        run.validate()?;
        plan.validate()?;
        if run.plan_id != plan.plan_id {
            bail!("run and immutable plan identities disagree");
        }
        let runs = self.repository.join("runs");
        secure_directory(&runs)?;
        let directory = runs.join(run.run_id.as_str());
        secure_directory(&directory)?;
        secure_directory(&directory.join("attempts"))?;
        write_immutable(&directory, "plan.json", plan)?;
        atomic_write(&directory, "run.json", run)
    }

    /// Atomically reserves every unit in a new campaign run.
    ///
    /// Returns `false` when the exact deterministic run was already reserved.
    ///
    /// # Errors
    ///
    /// Returns an error when another nonterminal run owns any selected unit or
    /// retained state conflicts with the deterministic run identity.
    pub(super) fn reserve_run(
        &self,
        run: &PackageUpdateRunV1,
        plan: &PackageUpdatePlanV1,
    ) -> Result<bool> {
        self.with_repository_lock(|| {
            if let Some(existing) = self.read_run(run.run_id.as_str())? {
                if existing.plan_digest != run.plan_digest
                    || existing.plan_id != run.plan_id
                    || existing.branch != run.branch
                    || existing.worktree != run.worktree
                    || existing.base_commit != run.base_commit
                {
                    bail!("deterministic run identity is already reserved with other state");
                }
                return Ok(false);
            }
            let selected = plan
                .units
                .iter()
                .map(|unit| &unit.unit_id)
                .collect::<std::collections::BTreeSet<_>>();
            for active in self
                .list_runs()?
                .into_iter()
                .filter(|candidate| !candidate.state.is_terminal())
            {
                let active_plan = self
                    .read_plan(active.plan_id.as_str())?
                    .ok_or_else(|| anyhow::anyhow!("active run plan is unavailable"))?;
                if active_plan
                    .units
                    .iter()
                    .any(|unit| selected.contains(&unit.unit_id))
                {
                    bail!(
                        "update unit {} is already reserved by active run {}",
                        active_plan
                            .units
                            .iter()
                            .find(|unit| selected.contains(&unit.unit_id))
                            .map(|unit| unit.unit_id.as_str())
                            .unwrap_or("unknown"),
                        active.run_id
                    );
                }
            }
            self.initialize_run(run, plan)?;
            Ok(true)
        })
    }

    /// Writes the rebuildable run projection after validating it.
    pub(super) fn write_run(&self, run: &PackageUpdateRunV1) -> Result<()> {
        run.validate()?;
        let directory = self.run_directory(run.run_id.as_str())?;
        atomic_write(&directory, "run.json", run)
    }

    /// Reads one exact run projection, when present.
    pub(super) fn read_run(&self, run_id: &str) -> Result<Option<PackageUpdateRunV1>> {
        validate_state_name(run_id, "run")?;
        let path = self.repository.join("runs").join(run_id).join("run.json");
        let Some(run) = read_optional(&path, "maintenance run")? else {
            return Ok(None);
        };
        let run: PackageUpdateRunV1 = run;
        run.validate()?;
        if run.run_id.as_str() != run_id {
            bail!("maintenance run identity does not match its path");
        }
        Ok(Some(run))
    }

    /// Lists all locally retained run projections in stable identity order.
    pub(super) fn list_runs(&self) -> Result<Vec<PackageUpdateRunV1>> {
        let directory = self.repository.join("runs");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).context("listing maintenance runs"),
        };
        let mut runs = Vec::new();
        for entry in entries {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("maintenance run index contains a non-directory entry");
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("maintenance run identity is not UTF-8"))?;
            if let Some(run) = self.read_run(&name)? {
                runs.push(run);
            }
        }
        runs.sort_by(|left, right| left.run_id.cmp(&right.run_id));
        Ok(runs)
    }

    /// Reads and verifies the complete authoritative journal prefix.
    pub(super) fn read_journal(&self, run_id: &str) -> Result<Vec<JournalEvent>> {
        let directory = self.run_directory(run_id)?;
        let path = directory.join("journal.ndjson");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).context("reading maintenance journal"),
        };
        if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
            bail!("maintenance journal exceeds size limit");
        }
        let mut events = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            events.push(canonical::from_slice(line, "maintenance journal event")?);
        }
        if !events.is_empty() {
            let _ = verify_journal(&events)?;
        }
        Ok(events)
    }

    /// Atomically stores deterministic attempt-zero patch and source evidence.
    pub(super) fn write_materialization(
        &self,
        record: &MaterializationRecordV1,
        patch: &[u8],
    ) -> Result<()> {
        record.validate()?;
        if patch.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
            bail!("materialization patch exceeds size limit");
        }
        let run = self
            .read_run(record.run_id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("materialization run is unavailable"))?;
        if run.plan_id != record.plan_id || run.attempt != record.attempt {
            bail!("materialization record does not match its run");
        }
        let attempt = self
            .run_directory(record.run_id.as_str())?
            .join("attempts")
            .join(record.attempt.to_string());
        secure_directory(&attempt)?;
        atomic_write_bytes(&attempt, "patch.diff", patch)?;
        atomic_write(&attempt, "materialization.json", record)
    }

    /// Stores immutable owner preimages before the first materialization edit.
    ///
    /// # Errors
    ///
    /// Returns an error when the set is empty, oversized, unsafe, or conflicts
    /// with a previously written intent.
    pub(super) fn write_materialization_intent(
        &self,
        run: &PackageUpdateRunV1,
        preimages: &[MaterializationPreimage],
    ) -> Result<()> {
        if preimages.is_empty() || preimages.len() > 64 {
            bail!("materialization preimage set is empty or oversized");
        }
        let mut seen = std::collections::BTreeSet::new();
        for preimage in preimages {
            if !preimage.path.starts_with("pkgs/")
                || !seen.insert(preimage.path.as_str())
                || preimage.contents.len() as u64 > MAX_STATE_DOCUMENT_BYTES
            {
                bail!("materialization preimage is unsafe or duplicated");
            }
        }
        let directory = self.run_directory(run.run_id.as_str())?.join("attempts/0");
        secure_directory(&directory)?;
        write_immutable(
            &directory,
            "materialization-intent.json",
            &preimages.to_vec(),
        )
    }

    /// Reads owner preimages retained for interrupted materialization recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when retained intent state is malformed.
    pub(super) fn read_materialization_intent(
        &self,
        run_id: &str,
    ) -> Result<Option<Vec<MaterializationPreimage>>> {
        let path = self
            .run_directory(run_id)?
            .join("attempts/0/materialization-intent.json");
        let Some(preimages): Option<Vec<MaterializationPreimage>> =
            read_optional(&path, "materialization intent")?
        else {
            return Ok(None);
        };
        if preimages.is_empty() || preimages.len() > 64 {
            bail!("materialization intent is empty or oversized");
        }
        let mut seen = std::collections::BTreeSet::new();
        for preimage in &preimages {
            let path = Path::new(&preimage.path);
            if !preimage.path.starts_with("pkgs/")
                || path.is_absolute()
                || path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir
                            | std::path::Component::CurDir
                            | std::path::Component::RootDir
                    )
                })
                || !seen.insert(preimage.path.as_str())
                || preimage.contents.len() as u64 > MAX_STATE_DOCUMENT_BYTES
            {
                bail!("materialization intent contains an unsafe preimage");
            }
        }
        Ok(Some(preimages))
    }

    /// Reads deterministic materialization evidence for a run, when present.
    pub(super) fn read_materialization(
        &self,
        run_id: &str,
    ) -> Result<Option<MaterializationRecordV1>> {
        let path = self
            .run_directory(run_id)?
            .join("attempts/0/materialization.json");
        let Some(record) = read_optional(&path, "materialization record")? else {
            return Ok(None);
        };
        let record: MaterializationRecordV1 = record;
        record.validate()?;
        if record.run_id.as_str() != run_id {
            bail!("materialization record belongs to another run");
        }
        Ok(Some(record))
    }

    /// Reads the retained cumulative canonical patch for the current attempt.
    pub(super) fn read_patch(&self, run_id: &str) -> Result<Option<Vec<u8>>> {
        let run = self
            .read_run(run_id)?
            .ok_or_else(|| anyhow::anyhow!("patch run is unavailable"))?;
        let path = self
            .run_directory(run_id)?
            .join("attempts")
            .join(run.attempt.to_string())
            .join("patch.diff");
        match path.symlink_metadata() {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > MAX_STATE_DOCUMENT_BYTES
                {
                    bail!("retained maintenance patch is unsafe or oversized");
                }
                Ok(Some(fs::read(path)?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("inspecting retained maintenance patch"),
        }
    }

    /// Stores one immutable gate set and its bounded per-gate logs.
    pub(super) fn write_gate_results(
        &self,
        record: &GateResultsV1,
        logs: &[(String, Vec<u8>)],
    ) -> Result<()> {
        record.validate()?;
        let attempt = self
            .run_directory(record.run_id.as_str())?
            .join("attempts")
            .join(record.attempt.to_string());
        secure_directory(&attempt)?;
        let digest =
            Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_GATE_RESULTS_V1, record)?;
        let phase_directory = attempt.join("gates").join(&record.phase);
        secure_directory(&phase_directory)?;
        let execution = phase_directory.join(digest.hex());
        secure_directory(&execution)?;
        let log_directory = execution.join("logs");
        secure_directory(&log_directory)?;
        if logs.len() != record.results.len() {
            bail!("gate log set does not match result set");
        }
        let mut retained = std::collections::BTreeSet::new();
        for (name, bytes) in logs {
            validate_state_name(name, "gate")?;
            if bytes.len() > 8 * 1024 * 1024 {
                bail!("gate log exceeds size limit");
            }
            let result = record
                .results
                .iter()
                .find(|result| result.gate_id == *name)
                .ok_or_else(|| anyhow::anyhow!("gate log identity is absent from result set"))?;
            let bytes_len = u64::try_from(bytes.len()).context("gate log length overflow")?;
            let digest = Sha256Digest::separated("aos.package-update-gate-log/v1", bytes);
            if !retained.insert(name)
                || result.log_bytes != bytes_len
                || result.log_digest != digest
            {
                bail!("gate log bytes disagree with retained result evidence");
            }
            write_immutable_bytes(&log_directory, &format!("{name}.log"), bytes)?;
        }
        write_immutable(&execution, "results.json", record)?;
        atomic_write(
            &phase_directory,
            "latest.json",
            &GateExecutionHead { digest },
        )
    }

    /// Reads and validates the atomically selected gate set for the current attempt.
    pub(super) fn read_gate_results(
        &self,
        run_id: &str,
        phase: &str,
    ) -> Result<Option<GateResultsV1>> {
        if !matches!(phase, "quick" | "final") {
            bail!("gate phase is invalid");
        }
        let run = self
            .read_run(run_id)?
            .ok_or_else(|| anyhow::anyhow!("gate run is unavailable"))?;
        let directory = self
            .run_directory(run_id)?
            .join("attempts")
            .join(run.attempt.to_string())
            .join("gates")
            .join(phase);
        let Some(head): Option<GateExecutionHead> =
            read_optional(&directory.join("latest.json"), "gate execution head")?
        else {
            return Ok(None);
        };
        let digest = head.digest.hex();
        let execution = directory.join(&digest);
        let metadata = execution
            .symlink_metadata()
            .context("inspecting retained gate execution")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("retained gate execution path is unsafe");
        }
        let record: GateResultsV1 = read_required(&execution.join("results.json"), "gate results")?;
        record.validate()?;
        if record.run_id.as_str() != run_id
            || record.phase != phase
            || record.attempt != run.attempt
        {
            bail!("gate results do not match their state path");
        }
        let actual =
            Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_GATE_RESULTS_V1, &record)?;
        if actual != head.digest {
            bail!("gate result content digest disagrees with its state path");
        }
        Ok(Some(record))
    }

    /// Reads one retained bounded gate log for the current attempt.
    pub(super) fn read_gate_log(
        &self,
        run_id: &str,
        phase: &str,
        gate_id: &str,
    ) -> Result<Vec<u8>> {
        let path = self.gate_log_path(run_id, phase, gate_id)?;
        let bytes = read_bounded_regular_file(&path, 8 * 1024 * 1024, "gate log")?;
        let results = self
            .read_gate_results(run_id, phase)?
            .ok_or_else(|| anyhow::anyhow!("gate execution is unavailable"))?;
        let result = results
            .results
            .iter()
            .find(|result| result.gate_id == gate_id)
            .ok_or_else(|| anyhow::anyhow!("gate is absent from the retained execution"))?;
        let length = u64::try_from(bytes.len()).context("gate log length overflow")?;
        let digest = Sha256Digest::separated("aos.package-update-gate-log/v1", &bytes);
        if result.log_bytes != length || result.log_digest != digest {
            bail!("retained gate log disagrees with result evidence");
        }
        Ok(bytes)
    }

    /// Resolves one validated retained gate-log path without reading it.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, missing run, or unsafe log.
    pub(super) fn gate_log_path(
        &self,
        run_id: &str,
        phase: &str,
        gate_id: &str,
    ) -> Result<PathBuf> {
        if !matches!(phase, "quick" | "final") {
            bail!("gate phase is invalid");
        }
        validate_state_name(gate_id, "gate")?;
        let run = self
            .read_run(run_id)?
            .ok_or_else(|| anyhow::anyhow!("gate run is unavailable"))?;
        let results = self
            .read_gate_results(run_id, phase)?
            .ok_or_else(|| anyhow::anyhow!("gate execution is unavailable"))?;
        if !results
            .results
            .iter()
            .any(|result| result.gate_id == gate_id)
        {
            bail!("gate is absent from the retained execution");
        }
        let digest =
            Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_GATE_RESULTS_V1, &results)?;
        let path = self
            .run_directory(run_id)?
            .join("attempts")
            .join(run.attempt.to_string())
            .join("gates")
            .join(phase)
            .join(digest.hex())
            .join("logs")
            .join(format!("{gate_id}.log"));
        let metadata = path
            .symlink_metadata()
            .context("inspecting retained gate log")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 8 * 1024 * 1024
        {
            bail!("retained gate log is unsafe or oversized");
        }
        Ok(path)
    }

    /// Stores one immutable untrusted adapter proposal before human acceptance.
    pub(super) fn write_agent_proposal(
        &self,
        task: &AgentTaskV1,
        result: &AgentResultV1,
    ) -> Result<()> {
        task.validate()?;
        result.validate_for(task)?;
        let run = self
            .read_run(task.run_id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("repair run is unavailable"))?;
        if task.plan_id != run.plan_id || task.attempt != run.attempt.saturating_add(1) {
            bail!("repair proposal does not match the current run generation");
        }
        let directory = self
            .run_directory(task.run_id.as_str())?
            .join("proposals")
            .join(task.attempt.to_string());
        secure_directory(&directory)?;
        write_immutable(&directory, "task.json", task)?;
        write_immutable(&directory, "result.json", result)
    }

    /// Reads the pending proposal for the next attempt, when one exists.
    pub(super) fn read_agent_proposal(
        &self,
        run: &PackageUpdateRunV1,
    ) -> Result<Option<(AgentTaskV1, AgentResultV1)>> {
        let attempt = run.attempt.saturating_add(1);
        let directory = self
            .run_directory(run.run_id.as_str())?
            .join("proposals")
            .join(attempt.to_string());
        let Some(task) = read_optional(&directory.join("task.json"), "repair-agent task")? else {
            return Ok(None);
        };
        let task: AgentTaskV1 = task;
        task.validate()?;
        let result: AgentResultV1 =
            read_optional(&directory.join("result.json"), "repair-agent result")?
                .ok_or_else(|| anyhow::anyhow!("repair proposal is missing its result"))?;
        result.validate_for(&task)?;
        if task.run_id != run.run_id || task.plan_id != run.plan_id || task.attempt != attempt {
            bail!("repair proposal state path disagrees with its identity");
        }
        Ok(Some((task, result)))
    }

    /// Stores one accepted repair attempt and its cumulative candidate patch.
    pub(super) fn write_repair_attempt(
        &self,
        run: &PackageUpdateRunV1,
        record: &RepairAttemptV1,
        patch: &[u8],
    ) -> Result<()> {
        record.validate()?;
        if record.run_id != run.run_id
            || record.plan_id != run.plan_id
            || record.parent_attempt != run.attempt
            || patch.len() as u64 > MAX_STATE_DOCUMENT_BYTES
            || Sha256Digest::separated("aos.package-update-patch/v1", patch)
                != record.candidate_digest
        {
            bail!("repair attempt does not match its run or retained candidate");
        }
        let directory = self
            .run_directory(run.run_id.as_str())?
            .join("attempts")
            .join(record.attempt.to_string());
        secure_directory(&directory)?;
        write_immutable_bytes(&directory, "patch.diff", patch)?;
        write_immutable(&directory, "repair.json", record)
    }

    /// Reads the complete ordered accepted repair lineage for one run.
    ///
    /// # Errors
    ///
    /// Returns an error when an expected attempt is absent, malformed, or
    /// does not form the run's exact monotonic lineage.
    pub(super) fn read_repair_attempts(
        &self,
        run: &PackageUpdateRunV1,
    ) -> Result<Vec<RepairAttemptV1>> {
        let mut records = Vec::with_capacity(run.attempt as usize);
        for attempt in 1..=run.attempt {
            let path = self
                .run_directory(run.run_id.as_str())?
                .join("attempts")
                .join(attempt.to_string())
                .join("repair.json");
            let record: RepairAttemptV1 = read_optional(&path, "repair attempt")?
                .ok_or_else(|| anyhow::anyhow!("repair attempt {attempt} is missing"))?;
            record.validate()?;
            if record.run_id != run.run_id
                || record.plan_id != run.plan_id
                || record.attempt != attempt
                || record.parent_attempt.checked_add(1) != Some(attempt)
            {
                bail!("repair attempt lineage disagrees with its run");
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Stores the immutable final local evidence dossier.
    pub(super) fn write_evidence(
        &self,
        evidence: &PackageUpdateEvidenceV1,
    ) -> Result<Sha256Digest> {
        evidence.validate()?;
        let directory = self.run_directory(evidence.run_id.as_str())?;
        write_immutable(&directory, "final-evidence.json", evidence)?;
        Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_EVIDENCE_V1, evidence)
    }

    /// Reads and validates a retained final local evidence dossier.
    pub(super) fn read_evidence(&self, run_id: &str) -> Result<Option<PackageUpdateEvidenceV1>> {
        let path = self.run_directory(run_id)?.join("final-evidence.json");
        let Some(evidence) = read_optional(&path, "package update evidence")? else {
            return Ok(None);
        };
        let evidence: PackageUpdateEvidenceV1 = evidence;
        evidence.validate()?;
        if evidence.run_id.as_str() != run_id {
            bail!("package update evidence belongs to another run");
        }
        Ok(Some(evidence))
    }

    /// Stores the immutable exact branch and pull-request publication result.
    pub(super) fn write_publication(&self, publication: &PullRequestPublicationV1) -> Result<()> {
        publication.validate()?;
        let run = self
            .read_run(publication.run_id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("publication run is unavailable"))?;
        if run.candidate_commit.as_ref() != Some(&publication.head)
            || run.evidence_digest != Some(publication.evidence_digest)
        {
            bail!("publication does not match the final-gated run");
        }
        let directory = self.run_directory(publication.run_id.as_str())?;
        write_immutable(&directory, "publication.json", publication)
    }

    /// Reads and validates the immutable publication result, when present.
    pub(super) fn read_publication(
        &self,
        run_id: &str,
    ) -> Result<Option<PullRequestPublicationV1>> {
        let path = self.run_directory(run_id)?.join("publication.json");
        let Some(publication) = read_optional(&path, "pull-request publication")? else {
            return Ok(None);
        };
        let publication: PullRequestPublicationV1 = publication;
        publication.validate()?;
        if publication.run_id.as_str() != run_id {
            bail!("pull-request publication belongs to another run");
        }
        Ok(Some(publication))
    }

    /// Stores the latest exact-head read-only remote observation atomically.
    pub(super) fn write_remote_observation(
        &self,
        observation: &PullRequestObservationV1,
    ) -> Result<()> {
        observation.validate()?;
        let publication = self
            .read_publication(observation.run_id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("remote observation has no publication"))?;
        if publication.pull_request_number != observation.pull_request_number
            || publication.head != observation.head
            || publication.base_branch != observation.base_branch
        {
            bail!("remote observation does not match its exact publication");
        }
        let directory = self.run_directory(observation.run_id.as_str())?;
        atomic_write(&directory, "remote-observation.json", observation)
    }

    /// Reads and validates the latest cached remote observation, when present.
    pub(super) fn read_remote_observation(
        &self,
        run_id: &str,
    ) -> Result<Option<PullRequestObservationV1>> {
        let path = self.run_directory(run_id)?.join("remote-observation.json");
        let Some(observation) = read_optional(&path, "pull-request observation")? else {
            return Ok(None);
        };
        let observation: PullRequestObservationV1 = observation;
        observation.validate()?;
        if observation.run_id.as_str() != run_id {
            bail!("pull-request observation belongs to another run");
        }
        Ok(Some(observation))
    }

    /// Appends one legal transition and updates the validated run projection.
    pub(super) fn transition(
        &self,
        run: &mut PackageUpdateRunV1,
        next: RunState,
        actor: ActorClass,
        now_unix: u64,
    ) -> Result<()> {
        self.with_repository_lock(|| {
            let events = self.read_journal(run.run_id.as_str())?;
            if let Some(state) = (!events.is_empty())
                .then(|| verify_journal(&events))
                .transpose()?
            {
                if state != run.state {
                    bail!("run projection disagrees with its journal");
                }
            } else if run.state != RunState::Observed {
                bail!("new journal must begin in observed state");
            }
            if !run.state.can_transition_to(next) {
                bail!("illegal maintenance run transition");
            }
            let sequence = u64::try_from(events.len())
                .context("journal length overflow")?
                .saturating_add(1);
            let previous = events.last().map(|event| event.record_digest);
            let event = JournalEvent::new(
                sequence,
                previous,
                run.run_id.clone(),
                Some(run.attempt),
                aos_maintain::identity::OperationId::parse("state-transition")?,
                actor,
                EventBindings {
                    plan: Some(run.plan_digest),
                    tree: None,
                    head: None,
                },
                JournalPayload::Transition {
                    from: run.state,
                    to: next,
                },
                format!("unix:{now_unix}"),
            )?;
            self.append_journal_event(run.run_id.as_str(), &event)?;
            run.state = next;
            run.updated_at_unix = now_unix;
            self.write_run(run)
        })
    }

    /// Appends a durable request before an external effect begins.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal disagrees with the run or the event
    /// cannot be appended atomically.
    pub(super) fn effect_intent(
        &self,
        run: &PackageUpdateRunV1,
        operation: &str,
        actor: ActorClass,
        request: Sha256Digest,
    ) -> Result<u64> {
        self.append_effect_event(
            run,
            operation,
            actor,
            JournalPayload::EffectIntent { request },
        )
    }

    /// Appends the observed result of one durable external-effect request.
    ///
    /// # Errors
    ///
    /// Returns an error when the intent is absent or mismatched, the journal
    /// disagrees with the run, or the event cannot be appended atomically.
    pub(super) fn effect_result(
        &self,
        run: &PackageUpdateRunV1,
        operation: &str,
        actor: ActorClass,
        intent_sequence: u64,
        outcome: aos_maintain::workflow::GateOutcome,
        output: Option<Sha256Digest>,
    ) -> Result<u64> {
        let events = self.read_journal(run.run_id.as_str())?;
        let intent = events
            .iter()
            .find(|event| event.journal_sequence == intent_sequence)
            .ok_or_else(|| anyhow::anyhow!("effect intent is absent from the journal"))?;
        if intent.operation.as_str() != operation
            || !matches!(intent.payload, JournalPayload::EffectIntent { .. })
        {
            bail!("effect result does not match its journaled intent");
        }
        self.append_effect_event(
            run,
            operation,
            actor,
            JournalPayload::EffectResult {
                intent_sequence,
                outcome,
                output,
            },
        )
    }

    fn append_effect_event(
        &self,
        run: &PackageUpdateRunV1,
        operation: &str,
        actor: ActorClass,
        payload: JournalPayload,
    ) -> Result<u64> {
        self.with_repository_lock(|| {
            let events = self.read_journal(run.run_id.as_str())?;
            if verify_journal(&events)? != run.state {
                bail!("run projection disagrees with its journal");
            }
            let sequence = u64::try_from(events.len())
                .context("journal length overflow")?
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("journal sequence overflow"))?;
            let event = JournalEvent::new(
                sequence,
                events.last().map(|event| event.record_digest),
                run.run_id.clone(),
                Some(run.attempt),
                aos_maintain::identity::OperationId::parse(operation)?,
                actor,
                EventBindings {
                    plan: Some(run.plan_digest),
                    tree: run.accepted_candidate,
                    head: run.candidate_commit.as_ref().map(|commit| {
                        Sha256Digest::separated(
                            "aos.package-update-commit/v1",
                            commit.value.as_bytes(),
                        )
                    }),
                },
                payload,
                format!("unix:{}", now_unix()?),
            )?;
            self.append_journal_event(run.run_id.as_str(), &event)?;
            Ok(sequence)
        })
    }

    /// Serializes a repository-scoped effect behind an exclusive local lock.
    pub(super) fn with_repository_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let lock_path = self.repository.join("controller.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .context("opening maintenance controller lock")?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .context("locking maintenance repository")?;
        operation()
    }

    /// Serializes a complete state-changing operation for one immutable plan.
    ///
    /// This lock is deliberately separate from the short repository lock used
    /// by journal appends. A command may retain this lease across long-running
    /// gates or network requests while still taking the repository lock for an
    /// atomic state transition.
    pub(super) fn acquire_operation_lease(&self, plan_id: &str) -> Result<OperationLease> {
        validate_state_name(plan_id, "plan")?;
        let directory = self.repository.join("operation-locks");
        secure_directory(&directory)?;
        let path = directory.join(format!("{plan_id}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .context("opening maintenance operation lease")?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .context("locking maintenance plan operation")?;
        Ok(OperationLease { _file: file })
    }

    /// Records an immutable provider identity's earliest observed time.
    pub(super) fn record_first_observed(&self, identity: &str, observed_at: u64) -> Result<u64> {
        let identity = identity.to_string();
        let values =
            self.record_first_observed_batch(std::slice::from_ref(&identity), observed_at)?;
        values
            .get(&identity)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("provider first-observed identity was not recorded"))
    }

    /// Records a provider response's identities with one atomic index update.
    pub(super) fn record_first_observed_batch(
        &self,
        identities: &[String],
        observed_at: u64,
    ) -> Result<BTreeMap<String, u64>> {
        for identity in identities {
            if identity.is_empty()
                || identity.len() > 4096
                || identity.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!("provider first-observed identity is invalid");
            }
        }

        self.with_provider_lock(|| {
            let path = self.root.join("provider-first-observed.json");
            let mut values: BTreeMap<String, u64> =
                read_optional(&path, "provider first-observed index")?.unwrap_or_default();
            let mut observed = BTreeMap::new();
            let mut changed = false;
            for identity in identities {
                let value = match values.get(identity) {
                    Some(value) => *value,
                    None => {
                        values.insert(identity.clone(), observed_at);
                        changed = true;
                        observed_at
                    }
                };
                observed.insert(identity.clone(), value);
            }
            if changed {
                atomic_write(&self.root, "provider-first-observed.json", &values)?;
            }
            Ok(observed)
        })
    }

    /// Pins an upstream identity to its first resolved byte hash.
    ///
    /// Re-observing the same unit/component/slot/upstream identity with a
    /// different hash is a supply-chain conflict, never an ordinary update.
    pub(super) fn record_source_identity(&self, identity: &str, hash: &str) -> Result<()> {
        if identity.is_empty()
            || identity.len() > 4096
            || !hash.starts_with("sha256-")
            || hash.len() > 128
        {
            bail!("source identity observation is invalid");
        }
        self.with_repository_lock(|| {
            let path = self.repository.join("source-identities.json");
            let mut values: BTreeMap<String, SourceIdentityRecord> =
                read_optional(&path, "source identity index")?.unwrap_or_default();
            let key = Sha256Digest::separated("aos.maintain.source-identity/v1", identity).hex();
            match values.get(&key) {
                Some(existing) if existing.identity != identity => {
                    bail!("source identity index digest collision")
                }
                Some(existing) if existing.hash != hash => {
                    bail!("the same upstream source identity resolved to different bytes")
                }
                Some(_) => return Ok(()),
                None => {}
            }
            values.insert(
                key,
                SourceIdentityRecord {
                    identity: identity.to_string(),
                    hash: hash.to_string(),
                },
            );
            atomic_write(&self.repository, "source-identities.json", &values)
        })
    }

    /// Claims one Repology request under the host-wide spacing and daily budget.
    pub(super) fn claim_repology_request(&self, now_unix: u64) -> Result<()> {
        self.with_provider_lock(|| {
            let path = self.root.join("repology-budget.json");
            let mut budget: RepologyBudget =
                read_optional(&path, "Repology request budget")?.unwrap_or_default();
            let day = now_unix / 86_400;
            if budget.day != day {
                budget = RepologyBudget {
                    day,
                    ..RepologyBudget::default()
                };
            }
            if now_unix < budget.retry_after_unix {
                bail!("Repology retry deadline has not elapsed");
            }
            if budget.requests >= 1_000 {
                bail!("Repology daily request budget is exhausted");
            }
            if now_unix < budget.last_request_unix.saturating_add(1) {
                bail!("Repology one-request-per-second lease is unavailable");
            }
            budget.requests += 1;
            budget.last_request_unix = now_unix;
            atomic_write(&self.root, "repology-budget.json", &budget)
        })
    }

    /// Stores exact bounded public provider bytes by their content identity.
    pub(super) fn store_provider_response(&self, bytes: &[u8]) -> Result<Sha256Digest> {
        if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
            bail!("provider response exceeds cache size limit");
        }
        let digest = Sha256Digest::separated("aos.maintain.provider-response/v1", bytes);
        let cache = cache_root()?.join("observations");
        secure_directory(&cache)?;
        let destination = cache.join(digest.hex());
        match destination.symlink_metadata() {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("provider response cache entry is not a regular file");
                }
                if fs::read(&destination)? != bytes {
                    bail!("provider response cache digest collision");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write_bytes(&cache, &digest.hex(), bytes)?;
            }
            Err(error) => return Err(error).context("inspecting provider response cache"),
        }
        Ok(digest)
    }

    /// Returns the protected state root for diagnostics.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// Creates and returns a protected scratch directory for one run phase.
    pub(super) fn scratch_directory(&self, run_id: &str, phase: &str) -> Result<PathBuf> {
        validate_state_name(run_id, "run")?;
        validate_state_name(phase, "phase")?;
        let scratch = self.run_directory(run_id)?.join("scratch").join(phase);
        secure_directory(&scratch)?;
        for child in ["home", "tmp", "cache"] {
            secure_directory(&scratch.join(child))?;
        }
        Ok(scratch)
    }

    fn run_directory(&self, run_id: &str) -> Result<PathBuf> {
        validate_state_name(run_id, "run")?;
        let directory = self.repository.join("runs").join(run_id);
        let metadata = directory
            .symlink_metadata()
            .context("inspecting maintenance run directory")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("maintenance run path is not a real directory");
        }
        Ok(directory)
    }

    fn append_journal_event(&self, run_id: &str, event: &JournalEvent) -> Result<()> {
        event.verify()?;
        let directory = self.run_directory(run_id)?;
        let path = directory.join("journal.ndjson");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .context("opening maintenance journal")?;
        let bytes = canonical::to_vec(event)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn with_provider_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_path = self.root.join("provider-state.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .context("opening provider-state lock")?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .context("locking provider state")?;
        operation()
    }
}

fn validate_state_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 96
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
        })
    {
        bail!("{label} identity is invalid");
    }
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RepologyBudget {
    day: u64,
    requests: u64,
    last_request_unix: u64,
    retry_after_unix: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceIdentityRecord {
    identity: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GateExecutionHead {
    digest: Sha256Digest,
}

/// Returns wall-clock Unix seconds for observational metadata only.
pub(super) fn now_unix() -> Result<u64> {
    std::time::UNIX_EPOCH
        .elapsed()
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn state_root(override_root: Option<&Path>) -> Result<PathBuf> {
    let root = if let Some(root) = override_root {
        root.to_path_buf()
    } else if let Some(root) = absolute_environment_path("XDG_STATE_HOME")? {
        root.join("aos/maintain")
    } else {
        let home = absolute_environment_path("HOME")?
            .ok_or_else(|| anyhow::anyhow!("HOME is required when XDG_STATE_HOME is unset"))?;
        home.join(".local/state/aos/maintain")
    };
    if !root.is_absolute() {
        bail!("maintenance state root must be absolute");
    }
    Ok(root)
}

fn cache_root() -> Result<PathBuf> {
    if let Some(root) = absolute_environment_path("XDG_CACHE_HOME")? {
        return Ok(root.join("aos/maintain"));
    }
    let home = absolute_environment_path("HOME")?
        .ok_or_else(|| anyhow::anyhow!("HOME is required when XDG_CACHE_HOME is unset"))?;
    Ok(home.join(".cache/aos/maintain"))
}

fn absolute_environment_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("{name} must contain an absolute path");
    }
    Ok(Some(path))
}

fn secure_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!(
                "maintenance state path is not a real directory: {}",
                path.display()
            );
        }
    } else {
        fs::create_dir_all(path)
            .with_context(|| format!("creating maintenance state directory {}", path.display()))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("protecting maintenance state directory {}", path.display()))?;
    Ok(())
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        bail!("{label} is unsafe or oversized");
    }
    fs::read(path).with_context(|| format!("reading {label}"))
}

fn atomic_write<T>(directory: &Path, name: &str, value: &T) -> Result<()>
where
    T: Serialize,
{
    let bytes = canonical::to_vec(value)?;
    if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
        bail!("maintenance state document exceeds size limit");
    }
    atomic_write_bytes(directory, name, &bytes)
}

fn atomic_write_bytes(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .context("creating temporary maintenance state document")?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(directory.join(name))
        .map_err(|error| error.error)
        .context("publishing maintenance state document")?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn write_immutable<T>(directory: &Path, name: &str, value: &T) -> Result<()>
where
    T: Serialize + DeserializeOwned,
{
    let destination = directory.join(name);
    if let Ok(metadata) = destination.symlink_metadata() {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("immutable maintenance object is not a regular file");
        }
        let existing: T = read_required(&destination, "immutable maintenance object")?;
        let expected = canonical::to_vec(value)?;
        let actual = canonical::to_vec(&existing)?;
        if actual != expected {
            bail!("immutable maintenance object digest collision");
        }
        return Ok(());
    }
    atomic_write(directory, name, value)
}

fn write_immutable_bytes(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let destination = directory.join(name);
    match destination.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("immutable maintenance byte object is not a regular file");
            }
            if fs::read(&destination)? != bytes {
                bail!("immutable maintenance byte object collision");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_bytes(directory, name, bytes)
        }
        Err(error) => Err(error).context("inspecting immutable maintenance byte object"),
    }
}

fn read_optional<T>(path: &Path, label: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    match path.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("{label} path is not a regular file");
            }
            Ok(Some(read_required(path, label)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {label}")),
    }
}

fn read_required<T>(path: &Path, label: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let file = File::open(path).with_context(|| format!("opening {label}"))?;
    let length = file.metadata()?.len();
    if length > MAX_STATE_DOCUMENT_BYTES {
        bail!("{label} exceeds size limit");
    }
    let capacity = usize::try_from(length).context("state document length does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_STATE_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
        bail!("{label} exceeds size limit");
    }
    canonical::from_slice(&bytes, label)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use aos_maintain::envelope::{GitObjectFormat, GitObjectId};
    use aos_maintain::identity::{PlanId, RunId};
    use aos_maintain::run::{ConfinementEvidence, GateResult};
    use aos_maintain::workflow::GateOutcome;

    use super::*;

    #[test]
    fn atomic_documents_are_canonical_and_round_trip() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let values = BTreeMap::from([("answer".to_string(), 42_u64)]);
        atomic_write(temporary.path(), "value.json", &values)?;

        let bytes = fs::read(temporary.path().join("value.json"))?;
        assert_eq!(bytes, br#"{"answer":42}"#);
        let loaded: BTreeMap<String, u64> =
            read_required(&temporary.path().join("value.json"), "fixture")?;
        assert_eq!(loaded, values);
        Ok(())
    }

    #[test]
    fn state_directories_reject_symlinks() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("target");
        fs::create_dir(&target)?;
        let link = temporary.path().join("link");
        symlink(&target, &link)?;

        assert!(secure_directory(&link).is_err());
        Ok(())
    }

    #[test]
    fn repology_budget_is_host_wide_and_day_bounded() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };

        store.claim_repology_request(100_000)?;
        assert!(store.claim_repology_request(100_000).is_err());
        store.claim_repology_request(100_001)?;
        Ok(())
    }

    #[test]
    fn first_observed_batch_preserves_each_identitys_earliest_time() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };
        let initial = vec!["provider:a".to_string(), "provider:b".to_string()];
        assert_eq!(
            store.record_first_observed_batch(&initial, 200)?,
            BTreeMap::from([
                ("provider:a".to_string(), 200),
                ("provider:b".to_string(), 200),
            ])
        );

        let repeated = vec!["provider:b".to_string(), "provider:c".to_string()];
        assert_eq!(
            store.record_first_observed_batch(&repeated, 300)?,
            BTreeMap::from([
                ("provider:b".to_string(), 200),
                ("provider:c".to_string(), 300),
            ])
        );
        assert!(
            store
                .record_first_observed_batch(&["provider:\n".to_string()], 400)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn source_identity_rejects_mutable_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };

        store.record_source_identity("unit\0main\0source\0v1", "sha256-first")?;
        store.record_source_identity("unit\0main\0source\0v1", "sha256-first")?;
        assert!(
            store
                .record_source_identity("unit\0main\0source\0v1", "sha256-second")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn operation_lease_excludes_the_same_plan_only() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };

        let lease = store.acquire_operation_lease("plan-one")?;
        let same = OpenOptions::new()
            .read(true)
            .write(true)
            .open(store.repository.join("operation-locks/plan-one.lock"))?;
        assert!(
            rustix::fs::flock(&same, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err()
        );
        let other = store.acquire_operation_lease("plan-two")?;

        drop(other);
        drop(lease);
        rustix::fs::flock(&same, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(())
    }

    #[test]
    fn gate_retries_select_exact_latest_execution_and_verify_logs() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };
        let run_id = RunId::parse("run-fixture")?;
        let plan_id = PlanId::parse("plan-fixture")?;
        let run = PackageUpdateRunV1 {
            schema: aos_maintain::PACKAGE_UPDATE_RUN_V1.to_string(),
            run_id: run_id.clone(),
            plan_id: plan_id.clone(),
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            state: RunState::PolicyValid,
            branch: "dplecki/upgrade-fixture".to_string(),
            worktree: "/tmp/aos-maintain-state-fixture".to_string(),
            worktree_cleaned: false,
            accepted_candidate: None,
            candidate_commit: None,
            evidence_digest: None,
            base_commit: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "0".repeat(40),
            },
            attempt: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        let runs = store.repository.join("runs");
        secure_directory(&runs)?;
        let run_directory = runs.join(run_id.as_str());
        secure_directory(&run_directory)?;
        store.write_run(&run)?;

        let first_log = b"first".to_vec();
        let second_log = b"second".to_vec();
        let record = |log: &[u8], outcome| GateResultsV1 {
            schema: aos_maintain::PACKAGE_UPDATE_GATE_RESULTS_V1.to_string(),
            run_id: run_id.clone(),
            plan_id: plan_id.clone(),
            attempt: 0,
            phase: "quick".to_string(),
            candidate_digest: Sha256Digest::of_bytes(b"candidate"),
            confinement: ConfinementEvidence {
                backend: "aos.linux-userns-landlock/v2".to_string(),
                landlock_abi: 4,
                filesystem_policy_digest: Sha256Digest::of_bytes(b"fs"),
                resource_limits_digest: Sha256Digest::of_bytes(b"limits"),
                private_user_namespace: true,
                private_process_namespaces: true,
                network_isolated: true,
                worker_tree_reaped: true,
                resource_limited: true,
                nix_sandbox_verified: true,
            },
            results: vec![GateResult {
                gate_id: "fmt".to_string(),
                argv: vec!["aos".to_string(), "fmt".to_string()],
                outcome,
                exit_code: Some(if outcome == GateOutcome::Success {
                    0
                } else {
                    1
                }),
                log_digest: Sha256Digest::separated("aos.package-update-gate-log/v1", log),
                log_bytes: log.len() as u64,
                elapsed_ms: 1,
            }],
            completed_at_unix: 10,
        };
        let first = record(&first_log, GateOutcome::Failure);
        store.write_gate_results(&first, &[("fmt".to_string(), first_log)])?;
        let second = record(&second_log, GateOutcome::Success);
        store.write_gate_results(&second, &[("fmt".to_string(), second_log.clone())])?;

        assert_eq!(
            store.read_gate_results(run_id.as_str(), "quick")?,
            Some(second)
        );
        assert_eq!(
            store.read_gate_log(run_id.as_str(), "quick", "fmt")?,
            second_log
        );
        let path = store.gate_log_path(run_id.as_str(), "quick", "fmt")?;
        fs::write(path, b"tampered")?;
        assert!(
            store
                .read_gate_log(run_id.as_str(), "quick", "fmt")
                .is_err()
        );
        Ok(())
    }
}
