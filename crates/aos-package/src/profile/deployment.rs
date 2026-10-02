//! Publishes profile links from the native deployment generation journal.
//!
//! A durable publication record associates each transaction sequence with an
//! already staged package generation. Effects commit before the `current` link
//! moves; recovery repairs that link from the committed journal. Authentication
//! and immutable artifact admission belong to the caller's deployment store.

use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use serde::{Deserialize, Serialize};

use super::{Generation, Profile, atomic_write};
use crate::deployment::model::Deployment;
use crate::deployment::transaction::{DeploymentStore, Transactions, journal_limits};

/// Reads one explicitly selected checked result from a committed profile generation.
///
/// The native journal remains authoritative: publication records must match its
/// sequence and content, and pending activation prevents a result handoff.
/// No operation-name discovery or handler execution occurs at this boundary.
///
/// # Errors
/// Returns an error for missing or inconsistent journals/publication records,
/// pending activation, an uncommitted profile generation, or an unknown effect.
pub fn committed_result(
    profile: &std::path::Path,
    generation: u32,
    effect: &str,
) -> Result<serde_json::Value> {
    committed_generation(profile, generation)?
        .outputs
        .get(effect)
        .cloned()
        .context("selected effect has no committed result")
}

/// Reads the checked native deployment published as a particular profile generation.
///
/// # Errors
/// Returns an error for missing or inconsistent authoritative journals, pending
/// activation, or a generation that has no committed native publication.
pub fn committed_generation(
    profile: &std::path::Path,
    generation: u32,
) -> Result<crate::deployment::transaction::Generation> {
    read_committed_generation(profile, generation, false)
}

/// Reads an already committed generation while later activation is pending.
///
/// This recovery-only inspection never exposes a pending desired generation or
/// executes effects. Mutating consumers must still recover before changing state.
///
/// # Errors
/// Returns an error for absent or inconsistent committed publication records,
/// malformed journals, or a requested generation that has not committed.
pub fn committed_generation_during_recovery(
    profile: &std::path::Path,
    generation: u32,
) -> Result<crate::deployment::transaction::Generation> {
    read_committed_generation(profile, generation, true)
}

/// Resolves the latest committed profile publication without following `current`.
///
/// Later pending work is permitted for boot recovery. An absent committed journal
/// identity returns `None`, including a prepared first activation; prepared state
/// never becomes a committed generation merely because a marker exists.
///
/// # Errors
/// Returns an error for invalid journals or inconsistent committed publication.
pub fn current_committed_generation(profile: &std::path::Path) -> Result<Option<u32>> {
    let directory = profile.join("deployment");
    if !directory.join("generations.journal").exists() {
        ensure!(
            !directory.join("effects.journal").exists(),
            "profile deployment journal is partially initialized"
        );
        return Ok(None);
    }
    ensure!(
        directory.join("effects.journal").is_file(),
        "profile effect journal is absent"
    );
    let transactions = crate::deployment::transaction::inspect(&directory, journal_limits())?;
    let Some(committed) = transactions.current() else {
        return Ok(None);
    };
    let publication = checked_publication(profile, committed)?;
    Ok(Some(publication.profile_generation))
}

/// Reports prepared native work without resuming or exposing it as committed.
///
/// # Errors
/// Returns an error for invalid journals, partial initialization, or lock contention.
pub fn has_pending_deployment(profile: &std::path::Path) -> Result<bool> {
    let directory = profile.join("deployment");
    if !directory.join("generations.journal").exists() {
        ensure!(
            !directory.join("effects.journal").exists(),
            "profile deployment journal is partially initialized"
        );
        return Ok(false);
    }
    ensure!(
        directory.join("effects.journal").is_file(),
        "profile effect journal is absent"
    );
    let snapshot = crate::deployment::transaction::inspect(&directory, journal_limits())?;
    Ok(requires_recovery(&snapshot))
}

fn read_committed_generation(
    profile: &std::path::Path,
    generation: u32,
    allow_later_pending: bool,
) -> Result<crate::deployment::transaction::Generation> {
    let directory = profile.join("deployment");
    ensure!(
        directory.join("generations.journal").is_file()
            && directory.join("effects.journal").is_file(),
        "committed profile deployment journals are absent or incomplete"
    );
    let transactions = crate::deployment::transaction::inspect(&directory, journal_limits())?;
    ensure!(
        allow_later_pending || !requires_recovery(&transactions),
        "profile activation is still pending"
    );
    for committed in transactions.generations().values() {
        let publication = checked_publication(profile, committed)?;
        if publication.profile_generation == generation {
            return Ok(committed.clone());
        }
    }
    anyhow::bail!("profile generation has no committed native deployment")
}

fn requires_recovery(snapshot: &crate::deployment::transaction::Snapshot) -> bool {
    snapshot.has_pending_work()
        || snapshot.incomplete_tail_bytes() != 0
        || snapshot.activation().incomplete_tail_bytes != 0
}

// Both records are read while the authoritative generation journal remains
// shared-locked, so publication and marker checks cannot race another commit.
fn checked_publication(
    profile: &std::path::Path,
    committed: &crate::deployment::transaction::Generation,
) -> Result<Publication> {
    let path = profile
        .join("deployment/publications")
        .join(format!("{}.json", committed.sequence));
    let publication: Publication =
        serde_json::from_slice(&crate::native_deployment::read_regular_document(&path)?)?;
    ensure!(
        publication.sequence == committed.sequence && publication.content == committed.content,
        "profile publication differs from committed deployment"
    );
    let marker = profile.join(format!(
        "gen-{}/native-deployment.json",
        publication.profile_generation
    ));
    let marker: Publication =
        serde_json::from_slice(&crate::native_deployment::read_regular_document(&marker)?)?;
    ensure!(
        marker.sequence == publication.sequence
            && marker.content == publication.content
            && marker.profile_generation == publication.profile_generation,
        "generation marker differs from committed publication"
    );
    Ok(publication)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    sequence: u64,
    content: String,
    profile_generation: u32,
}

/// Coordinates effect completion and publication of an installed profile tree.
pub struct ProfileDeployment<'a, S> {
    profile: &'a Profile,
    transactions: Transactions<S>,
}

impl<'a, S: DeploymentStore> ProfileDeployment<'a, S> {
    /// Opens the profile's native journals with caller-authenticated retention.
    ///
    /// # Errors
    /// Returns an error for invalid journal state, lock contention, or directory
    /// creation failure. The store must admit retained as well as new inputs.
    pub fn open(profile: &'a Profile, store: S, limits: JournalLimits) -> Result<Self> {
        let directory = profile.path.join("deployment");
        fs::create_dir_all(directory.join("publications"))?;
        let transactions = Transactions::open(&directory, store, limits)?;
        Ok(Self {
            profile,
            transactions,
        })
    }

    /// Resumes pending effects and repairs the profile's committed pointer.
    ///
    /// # Errors
    /// Returns an error for failed admission or effect recovery, absent staged
    /// trees, inconsistent publication records, or failed link publication.
    pub fn recover(&mut self, cancellation: &CancellationToken) -> Result<()> {
        self.transactions.resume(cancellation)?;
        self.publish_current()
    }

    /// Borrows the authoritative committed desired deployment after recovery.
    pub fn current(&self) -> Option<&crate::deployment::transaction::Generation> {
        self.transactions.current()
    }

    pub(crate) fn set_observer(
        &mut self,
        observer: Option<Box<dyn aos_ability_runtime::activation::BoundaryObserver>>,
    ) {
        self.transactions.set_observer(observer);
    }

    pub(crate) fn recovery_evaluation(&self) -> Result<Option<(std::path::PathBuf, Deployment)>> {
        let Some(sequence) = self.transactions.pending_sequence() else {
            return Ok(None);
        };
        let desired = self
            .transactions
            .pending()
            .context("pending sequence has no desired deployment")?;
        let publication: Publication =
            serde_json::from_slice(&fs::read(self.publication_path(sequence))?)?;
        ensure!(
            publication.sequence == sequence && publication.content == desired.id()?,
            "pending observer publication differs from its native journal"
        );
        let directory = self
            .profile
            .path
            .join(format!("gen-{}", publication.profile_generation));
        let marker: Publication =
            serde_json::from_slice(&fs::read(directory.join("native-deployment.json"))?)?;
        ensure!(
            marker.sequence == publication.sequence
                && marker.content == publication.content
                && marker.profile_generation == publication.profile_generation,
            "pending observer descriptor has an inconsistent profile marker"
        );
        Ok(Some((directory.join("evaluation.json"), desired.clone())))
    }

    /// Releases an old profile generation through its authoritative native journal.
    ///
    /// The profile tree and publication remain available until the caller removes
    /// them. Repeated calls after a completed release can finish interrupted tree
    /// deletion without attempting to release the same store roots twice.
    ///
    /// # Errors
    /// Returns an error for pending work, a current or inconsistent publication,
    /// or journal and artifact release failures.
    pub fn prune(&mut self, generation: &Generation) -> Result<()> {
        ensure!(
            self.transactions.pending().is_none(),
            "cannot prune during pending activation"
        );
        let marker: Publication =
            serde_json::from_slice(&fs::read(generation.path.join("native-deployment.json"))?)?;
        let publication: Publication =
            serde_json::from_slice(&fs::read(self.publication_path(marker.sequence))?)?;
        ensure!(
            marker.sequence == publication.sequence
                && marker.content == publication.content
                && marker.profile_generation == generation.number
                && publication.profile_generation == generation.number,
            "pruning publication differs from profile generation"
        );
        let current = self
            .transactions
            .current()
            .context("cannot prune without a current native generation")?;
        ensure!(
            marker.sequence < current.sequence,
            "cannot prune the current native generation"
        );
        if let Some(committed) = self.transactions.generations().get(&marker.sequence) {
            ensure!(
                committed.content == marker.content,
                "pruning publication differs from native journal"
            );
            self.transactions.prune(marker.sequence)?;
        }
        Ok(())
    }

    /// Activates a desired deployment and publishes its completed profile tree.
    ///
    /// The generation must contain its final payload roots, metadata snapshot,
    /// and merged FHS tree before calling this method. Callers must evaluate and
    /// authenticate the exact desired package set before staging it.
    ///
    /// # Errors
    /// Returns an error when recovery fails, the generation belongs to another
    /// profile, payload roots differ, durable preparation fails, or activation
    /// or publication cannot finish. A failed activation leaves `current` intact.
    pub fn apply(
        &mut self,
        deployment: &Deployment,
        generation: &Generation,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.recover(cancellation)?;
        ensure!(
            generation.path == self.profile.path.join(format!("gen-{}", generation.number)),
            "staged generation belongs to another profile"
        );
        let selected: BTreeSet<_> = deployment
            .artifacts()
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect();
        let roots = generation.roots()?;
        let staged: BTreeSet<_> = roots
            .iter()
            .map(|(_, path)| path.to_str().context("profile root is not UTF-8"))
            .collect::<Result<_>>()?;
        ensure!(
            staged == selected,
            "profile payload roots differ from deployment"
        );
        sync_tree(&generation.path)?;
        fs::File::open(&self.profile.path)?.sync_all()?;

        let sequence = self.transactions.next_sequence()?;
        let publication = Publication {
            sequence,
            content: deployment.id()?,
            profile_generation: generation.number,
        };
        let marker = generation.path.join("native-deployment.json");
        atomic_write(&marker, &serde_json::to_vec(&publication)?)?;
        fs::File::open(&marker)?.sync_all()?;
        fs::File::open(&generation.path)?.sync_all()?;
        let path = self.publication_path(sequence);
        atomic_write(&path, &serde_json::to_vec(&publication)?)?;
        fs::File::open(&path)?.sync_all()?;
        fs::File::open(path.parent().context("publication directory is absent")?)?.sync_all()?;

        self.transactions.apply(deployment, cancellation)?;
        self.publish_current()
    }

    fn publication_path(&self, sequence: u64) -> std::path::PathBuf {
        self.profile
            .path
            .join("deployment/publications")
            .join(format!("{sequence}.json"))
    }

    fn publish_current(&self) -> Result<()> {
        let Some(committed) = self.transactions.current() else {
            return Ok(());
        };
        let publication: Publication = serde_json::from_slice(
            &fs::read(self.publication_path(committed.sequence))
                .context("reading committed profile publication")?,
        )?;
        ensure!(
            publication.sequence == committed.sequence && publication.content == committed.content,
            "profile publication differs from committed deployment"
        );
        let generation = Generation {
            number: publication.profile_generation,
            path: self
                .profile
                .path
                .join(format!("gen-{}", publication.profile_generation)),
        };
        ensure!(generation.path.is_dir(), "committed profile tree is absent");
        self.profile.switch_to(&generation)?;
        crate::profile::meta::rebuild_meta(
            self.profile,
            &generation,
            &crate::registry::RegistrySet::new(Vec::new()),
        )?;
        fs::File::open(self.profile.path.join("state.json"))?.sync_all()?;
        fs::File::open(&self.profile.path)?.sync_all()?;
        Ok(())
    }
}

/// Flushes staged profile entries without following their store-root symlinks.
fn sync_tree(path: &std::path::Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            sync_tree(&entry.path())?;
        } else if file_type.is_file() {
            fs::File::open(entry.path())?.sync_all()?;
        } else {
            ensure!(
                file_type.is_symlink(),
                "staged profile contains a special file"
            );
        }
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use aos_ability_plan::module_graph::Effect;
    use serde_json::json;

    use super::*;
    use crate::deployment::handler::HandlerArtifacts;
    use crate::deployment::model::ResolvedPackages;
    use crate::types::ProfileScope;

    #[derive(Default)]
    struct Store {
        reject: bool,
        fail_at: Option<usize>,
        retains: usize,
    }

    impl HandlerArtifacts for Store {
        fn retain(&mut self, _: &Effect) -> Result<()> {
            bail!("empty profile must not dispatch a handler")
        }

        fn release(&mut self, _: &Effect) -> Result<()> {
            bail!("empty profile must not release a handler")
        }
    }

    impl DeploymentStore for Store {
        fn retain_generation(&mut self, _: &str, _: &Deployment) -> Result<()> {
            self.retains += 1;
            ensure!(!self.reject, "artifact admission rejected");
            ensure!(
                self.fail_at != Some(self.retains),
                "interrupted during pending generation"
            );
            Ok(())
        }

        fn release_generation(&mut self, _: &str, _: &Deployment) -> Result<()> {
            Ok(())
        }
    }

    fn deployment() -> Deployment {
        let resolved = ResolvedPackages {
            system: "x86_64-linux".into(),
            artifacts: Vec::new(),
            modules: Vec::new(),
        };
        Deployment::decode(
            &serde_json::to_vec(&json!({
                "schema": "aos.package.transaction",
                "scope": ["profile", "test"],
                "system": resolved.system,
                "artifacts": [],
                "retire": [],
                "inputs": [],
                "packages": [],
                "graph": {"schema": "aos.activation.graph", "nodes": {}, "order": []}
            }))
            .unwrap(),
            &resolved,
        )
        .unwrap()
    }

    #[test]
    fn recovery_repairs_link_from_committed_transaction() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let first = profile.new_generation().unwrap();
        profile.switch_to(&first).unwrap();
        let second = profile.new_generation().unwrap();
        let cancellation = CancellationToken::default();

        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer
            .apply(&deployment(), &second, &cancellation)
            .unwrap();
        drop(consumer);
        // Represents interruption before the frontend publishes the new link.
        profile.switch_to(&first).unwrap();

        let mut reopened =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        reopened.recover(&cancellation).unwrap();

        assert_eq!(
            profile.current_generation().unwrap().unwrap().number,
            second.number
        );
        assert_eq!(reopened.transactions.current().unwrap().sequence, 1);
    }

    #[test]
    fn recovery_selects_exact_sequence_when_desired_content_repeats() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let first = profile.new_generation().unwrap();
        let second = profile.new_generation().unwrap();
        let cancellation = CancellationToken::default();
        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer
            .apply(&deployment(), &first, &cancellation)
            .unwrap();
        drop(consumer);

        let mut consumer = ProfileDeployment::open(
            &profile,
            Store {
                fail_at: Some(2),
                ..Store::default()
            },
            JournalLimits::default(),
        )
        .unwrap();
        assert!(
            consumer
                .apply(&deployment(), &second, &cancellation)
                .is_err()
        );
        let (descriptor, desired) = consumer.recovery_evaluation().unwrap().unwrap();
        assert_eq!(descriptor, second.path.join("evaluation.json"));
        assert_eq!(desired.id().unwrap(), deployment().id().unwrap());
        assert_eq!(consumer.transactions.pending_sequence(), Some(2));
        drop(consumer);
        fs::remove_file(profile.current_path()).unwrap();

        assert_eq!(
            current_committed_generation(&profile.path).unwrap(),
            Some(first.number)
        );
        assert!(has_pending_deployment(&profile.path).unwrap());
        assert!(committed_generation(&profile.path, first.number).is_err());
        committed_generation_during_recovery(&profile.path, first.number).unwrap();

        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer.recover(&cancellation).unwrap();
        drop(consumer);
        assert_eq!(
            current_committed_generation(&profile.path).unwrap(),
            Some(second.number)
        );
    }

    #[test]
    fn rejected_artifacts_preserve_current_profile() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let first = profile.new_generation().unwrap();
        profile.switch_to(&first).unwrap();
        let second = profile.new_generation().unwrap();
        let mut consumer = ProfileDeployment::open(
            &profile,
            Store {
                reject: true,
                ..Store::default()
            },
            JournalLimits::default(),
        )
        .unwrap();

        assert!(
            consumer
                .apply(&deployment(), &second, &CancellationToken::default())
                .is_err()
        );

        assert_eq!(
            profile.current_generation().unwrap().unwrap().number,
            first.number
        );
        assert!(consumer.transactions.current().is_none());
    }

    #[test]
    fn recovery_publishes_staged_tree_after_pending_admission_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let previous = profile.new_generation().unwrap();
        profile.switch_to(&previous).unwrap();
        let staged = profile.new_generation().unwrap();
        let mut consumer = ProfileDeployment::open(
            &profile,
            Store {
                fail_at: Some(2),
                ..Store::default()
            },
            JournalLimits::default(),
        )
        .unwrap();

        assert!(
            consumer
                .apply(&deployment(), &staged, &CancellationToken::default())
                .is_err()
        );
        assert!(consumer.transactions.pending().is_some());
        assert_eq!(
            profile.current_generation().unwrap().unwrap().number,
            previous.number
        );
        drop(consumer);

        let mut recovered =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        recovered.recover(&CancellationToken::default()).unwrap();

        assert_eq!(
            profile.current_generation().unwrap().unwrap().number,
            staged.number
        );
        assert!(recovered.transactions.pending().is_none());
    }

    #[test]
    fn mismatched_publication_fails_before_moving_profile_link() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let generation = profile.new_generation().unwrap();
        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer
            .apply(&deployment(), &generation, &CancellationToken::default())
            .unwrap();
        fs::write(
            consumer.publication_path(1),
            serde_json::to_vec(&Publication {
                sequence: 1,
                content: "different".into(),
                profile_generation: generation.number,
            })
            .unwrap(),
        )
        .unwrap();

        assert!(consumer.recover(&CancellationToken::default()).is_err());
    }
    #[test]
    fn inspection_rejects_tampered_generation_marker() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let generation = profile.new_generation().unwrap();
        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer
            .apply(&deployment(), &generation, &CancellationToken::default())
            .unwrap();
        drop(consumer);
        assert_eq!(
            committed_generation(&profile.path, generation.number)
                .unwrap()
                .sequence,
            1
        );

        let marker = generation.path.join("native-deployment.json");
        let mut publication: Publication =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        publication.content = "changed".into();
        fs::write(marker, serde_json::to_vec(&publication).unwrap()).unwrap();

        assert!(committed_generation(&profile.path, generation.number).is_err());
    }

    #[test]
    fn pruning_releases_old_journal_generation_before_profile_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let first = profile.new_generation().unwrap();
        let second = profile.new_generation().unwrap();
        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        let cancellation = CancellationToken::default();
        consumer
            .apply(&deployment(), &first, &cancellation)
            .unwrap();
        consumer
            .apply(&deployment(), &second, &cancellation)
            .unwrap();

        assert!(consumer.prune(&second).is_err());
        consumer.prune(&first).unwrap();
        consumer.prune(&first).unwrap();

        assert!(!consumer.transactions.generations().contains_key(&1));
        assert!(first.path.is_dir());
        assert_eq!(
            profile.current_generation().unwrap().unwrap().number,
            second.number
        );
    }

    #[test]
    fn recovery_inspection_preserves_torn_journal_tail_and_never_exposes_pending_state() {
        use std::io::Write;

        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();
        let generation = profile.new_generation().unwrap();
        let mut consumer =
            ProfileDeployment::open(&profile, Store::default(), JournalLimits::default()).unwrap();
        consumer
            .apply(&deployment(), &generation, &CancellationToken::default())
            .unwrap();
        drop(consumer);
        let path = profile.path.join("deployment/generations.journal");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 1, 2])
            .unwrap();
        let bytes = fs::read(&path).unwrap();

        assert!(committed_generation(&profile.path, generation.number).is_err());
        assert!(has_pending_deployment(&profile.path).unwrap());
        assert_eq!(
            committed_generation_during_recovery(&profile.path, generation.number)
                .unwrap()
                .sequence,
            1
        );
        assert_eq!(
            current_committed_generation(&profile.path).unwrap(),
            Some(generation.number)
        );

        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn inspection_never_creates_journals_for_an_uninitialized_profile() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(temporary.path().into(), ProfileScope::User).unwrap();

        assert_eq!(current_committed_generation(&profile.path).unwrap(), None);
        assert!(!has_pending_deployment(&profile.path).unwrap());
        assert!(!profile.path.join("deployment").exists());
    }
}
