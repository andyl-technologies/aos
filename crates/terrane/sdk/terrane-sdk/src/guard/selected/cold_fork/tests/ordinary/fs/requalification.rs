//! Observes real native ACKs and injects narrowly armed source publication faults.
//!
//! These test hooks forward the original opaque native effect. Observations are
//! ordinary counters; only a successful public operation establishes its ACK.

use super::*;
use crate::store::native_publication_effects::collection::test_fs::TestClock;
use crate::store::{EffectFault, EffectFaultProbe, NativeEffectFailure, NativeFsEffect};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

/// Holds unarmed physical test faults and observations for one actual adapter.
#[derive(Default)]
pub(super) struct RequalificationHooks {
    mutation: Mutex<Option<(PathBuf, SourceMutation)>>,
    fired: AtomicUsize,
    ack: Mutex<Option<(PathBuf, bool)>>,
    attempts: AtomicUsize,
    successes: AtomicUsize,
    reads: Mutex<BTreeSet<PathBuf>>,
    blocked: Mutex<Option<PathBuf>>,
    blocked_reads: AtomicUsize,
    effects: Mutex<Option<Vec<RequalificationEffectObservation>>>,
}

/// Records the actual fixed effect classification and its planned path.
///
/// These observations supply no publication, qualification or ACK authority.
pub(in super::super) type RequalificationEffectObservation = (&'static str, Option<PathBuf>);

// Classifies the existing fixed fault-probe projection without inspecting bytes.
fn effect_classification(effect: &NativeFsEffect) -> (&'static str, Option<PathBuf>) {
    let (kind, path) = match effect.fault_probe() {
        EffectFaultProbe::SealRetirementBarrier(path) => ("SealRetirementBarrier", Some(path)),
        EffectFaultProbe::SealMutationPublication(path) => ("SealMutationPublication", Some(path)),
        EffectFaultProbe::SealRawPublication(path) => ("SealRawPublication", Some(path)),
        EffectFaultProbe::SealLeasePublication(path) => ("SealLeasePublication", Some(path)),
        EffectFaultProbe::SealPendingCreation(path) => ("SealPendingCreation", Some(path)),
        EffectFaultProbe::ObserveCurrentPair(path) => ("ObserveCurrentPair", Some(path)),
        EffectFaultProbe::ObserveLocalTriple(path) => ("ObserveLocalTriple", Some(path)),
        EffectFaultProbe::LocalFirstOwnership(path, _) => ("LocalFirstOwnership", Some(path)),
        EffectFaultProbe::LocalDeletion(path, _) => ("LocalDeletion", Some(path)),
        EffectFaultProbe::SealArtifact(path) => ("SealArtifact", Some(path)),
        EffectFaultProbe::CommitCreation(path) => ("CommitCreation", Some(path)),
        EffectFaultProbe::WriteNew(path) => ("WriteNew", Some(path)),
        EffectFaultProbe::FileSync => ("FileSync", None),
        EffectFaultProbe::DirectorySync(path) => ("DirectorySync", Some(path)),
        EffectFaultProbe::RenameNoReplace(path) => ("RenameNoReplace", Some(path)),
        EffectFaultProbe::Rename(path) => ("Rename", Some(path)),
        EffectFaultProbe::CopiedPreparation(path) => ("CopiedPreparation", Some(path)),
        EffectFaultProbe::CopiedBarrier(path) => ("CopiedBarrier", Some(path)),
        EffectFaultProbe::CopiedOwnership(path) => ("CopiedOwnership", Some(path)),
        EffectFaultProbe::PermanentLocalObservation(path) => {
            ("PermanentLocalObservation", Some(path))
        }
        EffectFaultProbe::PermanentLocalReclaim(path) => ("PermanentLocalReclaim", Some(path)),
        EffectFaultProbe::PermanentLocalProgress(path) => ("PermanentLocalProgress", Some(path)),
        EffectFaultProbe::Other => ("Other", None),
    };
    (kind, path.map(Path::to_owned))
}

/// Specifies one finite physical change without altering the sealed effect.
pub(in super::super) enum SourceMutation {
    /// Removes the independently checked source Original record.
    RemoveOriginal(PathBuf),
    /// Replaces actual checked bytes with a distinct physical incarnation.
    ReplaceRecord {
        /// Names the exact independently observed record.
        path: PathBuf,
        /// Retains its complete unchanged bytes.
        bytes: Vec<u8>,
        /// Retains its actual protection while changing its incarnation.
        permissions: std::fs::Permissions,
    },
    /// Invalidates protection of an actual consumed Original record.
    MakeControlWritable(PathBuf),
    /// Advances the actual retained clock beyond the signed token expiry.
    ExpireToken(TestClock),
}

impl CountingFs {
    /// Starts an opt-in observation of actual fixed effects.
    ///
    /// # Errors
    /// Rejects duplicate arming and poisoned fixture synchronization.
    pub(in super::super) fn observe_requalification_effects(&self) -> std::io::Result<()> {
        let mut observations = self
            .requalification
            .effects
            .lock()
            .map_err(|_| std::io::Error::other("source effect observation lock poisoned"))?;
        if observations.is_some() {
            return Err(std::io::Error::other(
                "source effect observation already armed",
            ));
        }
        *observations = Some(Vec::new());
        Ok(())
    }

    /// Returns fixed classifications captured before the exact native executor.
    ///
    /// # Errors
    /// Rejects unarmed observation and poisoned fixture synchronization.
    pub(in super::super) fn requalification_effect_observations(
        &self,
    ) -> std::io::Result<Vec<RequalificationEffectObservation>> {
        self.requalification
            .effects
            .lock()
            .map_err(|_| std::io::Error::other("source effect observation lock poisoned"))?
            .clone()
            .ok_or_else(|| std::io::Error::other("source effect observation not armed"))
    }

    /// Arms one physical change at the actual source lineage installation.
    ///
    /// # Errors
    /// Rejects duplicate arming and poisoned fixture synchronization.
    pub(in super::super) fn mutate_requalification_at_lineage(
        &self,
        directory: PathBuf,
        mutation: SourceMutation,
    ) -> std::io::Result<()> {
        let mut pending = self
            .requalification
            .mutation
            .lock()
            .map_err(|_| std::io::Error::other("source mutation lock poisoned"))?;
        if pending.is_some() {
            return Err(std::io::Error::other("source mutation already armed"));
        }
        self.requalification.fired.store(0, Ordering::SeqCst);
        *pending = Some((directory, mutation));
        Ok(())
    }

    /// Returns how many actual lineage effects triggered the armed mutation.
    pub(in super::super) fn requalification_mutations(&self) -> usize {
        self.requalification.fired.load(Ordering::SeqCst)
    }

    /// Observes an actual next native slot and optionally fails its real file sync.
    ///
    /// # Errors
    /// Rejects poisoned fixture synchronization.
    pub(in super::super) fn observe_requalification_ack(
        &self,
        slot: PathBuf,
        fail_sync: bool,
    ) -> std::io::Result<()> {
        *self
            .requalification
            .ack
            .lock()
            .map_err(|_| std::io::Error::other("source ACK lock poisoned"))? =
            Some((slot, fail_sync));
        self.requalification.attempts.store(0, Ordering::SeqCst);
        self.requalification.successes.store(0, Ordering::SeqCst);
        Ok(())
    }

    /// Returns submitted and successful native acknowledgment effect counts.
    pub(in super::super) fn requalification_ack_counts(&self) -> (usize, usize) {
        (
            self.requalification.attempts.load(Ordering::SeqCst),
            self.requalification.successes.load(Ordering::SeqCst),
        )
    }

    /// Clears actual pack observations before a genuine auxiliary Node lookup.
    ///
    /// # Errors
    /// Rejects poisoned fixture synchronization.
    pub(in super::super) fn clear_requalification_pack_reads(&self) -> std::io::Result<()> {
        self.requalification
            .reads
            .lock()
            .map_err(|_| std::io::Error::other("source pack observation lock poisoned"))?
            .clear();
        Ok(())
    }

    /// Returns actual pack names read by the genuine filesystem adapter.
    ///
    /// # Errors
    /// Rejects poisoned fixture synchronization.
    pub(in super::super) fn requalification_pack_reads(
        &self,
    ) -> std::io::Result<BTreeSet<PathBuf>> {
        Ok(self
            .requalification
            .reads
            .lock()
            .map_err(|_| std::io::Error::other("source pack observation lock poisoned"))?
            .clone())
    }

    /// Refuses one independently observed required-index pack read.
    ///
    /// # Errors
    /// Rejects poisoned fixture synchronization.
    pub(in super::super) fn block_requalification_pack(
        &self,
        path: PathBuf,
    ) -> std::io::Result<()> {
        *self
            .requalification
            .blocked
            .lock()
            .map_err(|_| std::io::Error::other("source pack fault lock poisoned"))? = Some(path);
        self.requalification
            .blocked_reads
            .store(0, Ordering::SeqCst);
        Ok(())
    }

    /// Returns real reads refused for the exact armed auxiliary pack.
    pub(in super::super) fn blocked_requalification_reads(&self) -> usize {
        self.requalification.blocked_reads.load(Ordering::SeqCst)
    }

    /// Records and optionally refuses one actual physical auxiliary pack read.
    ///
    /// # Errors
    /// Rejects poisoned fixture synchronization and the exact armed pack.
    pub(super) fn observe_requalification_pack(&self, path: &Path) -> std::io::Result<()> {
        if path.extension().is_none_or(|extension| extension != "pack") {
            return Ok(());
        }
        self.requalification
            .reads
            .lock()
            .map_err(|_| std::io::Error::other("source pack observation lock poisoned"))?
            .insert(path.to_owned());
        if self
            .requalification
            .blocked
            .lock()
            .map_err(|_| std::io::Error::other("source pack fault lock poisoned"))?
            .as_deref()
            == Some(path)
        {
            self.requalification
                .blocked_reads
                .fetch_add(1, Ordering::SeqCst);
            return Err(std::io::Error::other(
                "actual required-index pack read unavailable",
            ));
        }
        Ok(())
    }

    /// Forwards an actual opaque effect after any narrowly armed physical fault.
    ///
    /// # Errors
    /// Preserves native execution, physical fault and synchronization failures.
    pub(super) async fn execute_requalification_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let mutation = {
            let mut pending = self
                .requalification
                .mutation
                .lock()
                .map_err(|_| std::io::Error::other("source mutation lock poisoned"))?;
            let matches =
                pending
                    .as_ref()
                    .is_some_and(|(directory, _)| match effect.fault_probe() {
                        EffectFaultProbe::WriteNew(path)
                        | EffectFaultProbe::RenameNoReplace(path) => {
                            path.parent() == Some(directory.as_path())
                        }
                        _ => false,
                    });
            if matches {
                pending.take().map(|(_, mutation)| mutation)
            } else {
                None
            }
        };
        if let Some(mutation) = mutation {
            match mutation {
                SourceMutation::RemoveOriginal(path) => TokioLocalFs.remove_file(&path).await?,
                SourceMutation::ReplaceRecord {
                    path,
                    bytes,
                    permissions,
                } => {
                    // Install before removing the old inode so the incarnation
                    // cannot be recycled into an equal-byte replacement.
                    let replacement = path.with_extension("requalification-replacement");
                    TokioLocalFs.write_new(&replacement, &bytes).await?;
                    TokioLocalFs
                        .set_permissions(&replacement, permissions)
                        .await?;
                    TokioLocalFs.rename(&replacement, &path).await?;
                }
                SourceMutation::MakeControlWritable(path) => {
                    TokioLocalFs
                        .set_permissions(&path, std::fs::Permissions::from_mode(0o666))
                        .await?
                }
                SourceMutation::ExpireToken(clock) => clock.set(1011, 0),
            }
            self.requalification.fired.fetch_add(1, Ordering::SeqCst);
        }
        let ack = {
            let expected = self
                .requalification
                .ack
                .lock()
                .map_err(|_| std::io::Error::other("source ACK lock poisoned"))?;
            match (effect.fault_probe(), expected.as_ref()) {
                (EffectFaultProbe::SealMutationPublication(path), Some((expected, fail)))
                    if path == expected =>
                {
                    Some(*fail)
                }
                _ => None,
            }
        };
        if let Some(fail) = ack {
            self.requalification.attempts.fetch_add(1, Ordering::SeqCst);
            if fail {
                effect = effect.inject_test_faults(vec![EffectFault::BeforeFileSync]);
            }
        }
        {
            let mut observations =
                self.requalification.effects.lock().map_err(|_| {
                    std::io::Error::other("source effect observation lock poisoned")
                })?;
            if let Some(observations) = observations.as_mut() {
                observations.push(effect_classification(&effect));
            }
        }
        let outcome = TokioLocalFs.execute_retained_effect(effect).await;
        if ack.is_some() && outcome.is_ok() {
            self.requalification
                .successes
                .fetch_add(1, Ordering::SeqCst);
        }
        outcome
    }
}
