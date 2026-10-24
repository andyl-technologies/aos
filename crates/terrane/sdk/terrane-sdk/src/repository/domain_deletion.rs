//! Coordinates complete native domain deletion with a separately signed audit.
//!
//! Intent is a normal guarded commit before paired exclusion. The actual
//! deletion requalifies complete source inventory, whole heads and current Admin
//! alongside the exact pending audit head under canonical held exclusions.

use super::{Error, LocalAuthority, RegisteredDomainAudit, Repository, audit, audit_codec};
use crate::bucket::{
    BucketBinding, FileBucket,
    held::{HeldBuckets, SingleHeld},
};
use crate::domain::{ConfiguredDomainRoute, DomainDeletionAudit, DomainDeletionEvent};
use crate::guard::HistoryObservation;
use crate::selected_bridge::native_guard::domain_deletion::{self, QualifiedDomain};
use crate::store::{Clock, ContentValidator, LocalFs};
use terrane_format::identity::Identity;

impl<F, B, V, C> Repository<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    /// Deletes every native pack and index after complete current administration.
    ///
    /// The configured target must be this actual backend and its audit must be
    /// the independently registered private repository. No supplied root subset
    /// or bucket listing authorizes deletion. Source races after intent leave
    /// the route pending; failures after removal never reactivate it.
    ///
    /// # Errors
    /// Rejects wrong physical routing, incomplete CAPABILITIES inventory,
    /// missing Admin over any actual root, mismatched audit actors, changed
    /// whole records, expired requests and failed durable effects or completion.
    pub async fn delete_domain(
        &self,
        configured: &ConfiguredDomainRoute,
        authority: &LocalAuthority,
        audit: &RegisteredDomainAudit<'_, FileBucket<F, B, V>, C, F>,
    ) -> Result<Identity, Error> {
        let concrete = self.coordinator.guard();
        if concrete.config().storage_domain != configured.target().domain
            || concrete.store().root() != configured.target().root
            || self.local_backend_root.as_deref() != Some(configured.target().root.as_path())
            || audit.configured.target() != configured.target()
            || audit.configured.audit() != configured.audit()
            || audit.configured.control_ref() != configured.control_ref()
        {
            return Err(Error::Denied);
        }
        let administration = audit.administration().await?;
        let route_actor = administration.route_authority();
        let (initial_roots, initial_capabilities, initial_records, subject, token_id) = {
            let single = SingleHeld::acquire(concrete.store()).await?;
            let clock = concrete
                .clock()
                .retain_native_clock()
                .map_err(|_| Error::Denied)?;
            let held = concrete.held_guard(single.source(), clock)?;
            let observed = held.store().observe_publication_retained().await?;
            let qualified = domain_deletion::qualify(
                concrete,
                &held,
                &observed,
                authority.token(),
                "sdk",
                self.coordinator.timing(),
            )
            .await?;
            let actor = qualified
                .permissions
                .first()
                .map_or(route_actor, |access| access);
            let subject = actor.subject().to_owned();
            let token_id = *actor.token_id();
            (
                qualified.roots,
                qualified.capabilities,
                qualified.records,
                subject,
                token_id,
            )
        };
        let event = DomainDeletionEvent {
            domain: configured.target().domain.clone(),
            roots: initial_roots.clone(),
            subject,
            token_id,
        };
        let intent = audit.record_intent(&event).await?;
        #[cfg(all(test, feature = "tokio"))]
        test_pause::after_intent(concrete.store().root()).await?;

        {
            let audit_concrete = audit.repository.coordinator.guard();
            let pair = HeldBuckets::acquire(concrete.store(), audit_concrete.store()).await?;
            let source_clock = concrete
                .clock()
                .retain_native_clock()
                .map_err(|_| Error::Denied)?;
            let audit_clock = audit_concrete
                .clock()
                .retain_native_clock()
                .map_err(|_| Error::Denied)?;
            let source = concrete.held_guard(pair.source(), source_clock)?;
            let administrative = audit_concrete.held_guard(pair.destination(), audit_clock)?;
            let source_observed = source.store().observe_publication_retained().await?;
            let audit_observed = administrative
                .store()
                .observe_publication_retained()
                .await?;
            let current = domain_deletion::qualify(
                concrete,
                &source,
                &source_observed,
                authority.token(),
                "sdk",
                self.coordinator.timing(),
            )
            .await?;
            if current.capabilities != initial_capabilities
                || current.records != initial_records
                || current.roots != initial_roots
            {
                return Err(Error::Denied);
            }
            let audited = domain_deletion::qualify_audit(
                audit_concrete,
                &administrative,
                &audit_observed,
                audit.authority.token(),
                configured,
                audit.repository.coordinator.timing(),
            )
            .await?;
            let access = audited
                .permissions
                .iter()
                .find(|access| {
                    access.binding().reference == configured.control_ref()
                        && access.binding().path == b"/"
                })
                .ok_or(Error::Denied)?;
            let record = access.reference_record().ok_or(Error::Denied)?;
            if intent.terrane_v1_digest().map_err(|_| Error::Denied)? != record.commit {
                return Err(Error::Denied);
            }
            let snapshot = administrative
                .read_commit_snapshot_observed(
                    record.commit,
                    audit.authority.token(),
                    b"/",
                    "sdk",
                    HistoryObservation::held(audit_observed.identity()),
                )
                .await?;
            audit::validate_audit_root(&snapshot, audit.repository, &event.domain)?;
            let state = audit::validate_chain(&snapshot, &event.domain)?;
            let expected = audit_codec::decode(&audit_codec::encode(&event, 1, None)?)?;
            audit::check_actor(&event, &event.domain, access)?;
            if state.state != 1
                || state.event != expected.event
                || state.subject != expected.subject
                || state.token_id != expected.token_id
            {
                return Err(Error::Denied);
            }
            let QualifiedDomain {
                context: source_context,
                ..
            } = current;
            let context = domain_deletion::paired_context(source_context, audited.context);
            crate::bucket::domain_deletion::erase(
                self.coordinator.fs(),
                &source_observed,
                &audit_observed,
                &context,
            )
            .await?;
        }

        Ok(audit.record_completion(&event, &intent).await?)
    }
}

impl<F, B, V, C> RegisteredDomainAudit<'_, FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    /// Retains an independently checked signed active route under actual paired exclusion.
    ///
    /// This operator context controls routing only and supplies no caller rights
    /// over the target namespace.
    ///
    /// # Errors
    /// Rejects wrong actual bindings, absent or unsafe administrative authority,
    /// malformed retained chains and either pending or completed deletion.
    pub(crate) async fn held_active<D: Clock, const WRITABLE: bool>(
        &self,
        held: &crate::guard::Guard<crate::bucket::held::HeldBucket<'_, F, B, V, WRITABLE>, D>,
        observed: &crate::bucket::publication::SelectedObservation<'_>,
    ) -> Result<crate::selected_bridge::native_guard::GuardEffectContext, Error> {
        let qualified = domain_deletion::qualify_audit(
            self.repository.coordinator.guard(),
            held,
            observed,
            self.authority.token(),
            self.configured,
            self.repository.coordinator.timing(),
        )
        .await?;
        let access = qualified
            .permissions
            .iter()
            .find(|access| {
                access.binding().reference == self.configured.control_ref()
                    && access.binding().path == b"/"
            })
            .ok_or(Error::Denied)?;
        let record = access.reference_record().ok_or(Error::Denied)?;
        let snapshot = held
            .read_commit_snapshot_observed(
                record.commit,
                self.authority.token(),
                b"/",
                "sdk",
                HistoryObservation::held(observed.identity()),
            )
            .await?;
        audit::validate_audit_root(&snapshot, self.repository, &self.domain)?;
        let state = audit::validate_chain(&snapshot, &self.domain)?;
        if state.state != 0 {
            return Err(Error::Denied);
        }
        Ok(qualified.context)
    }
}

#[cfg(all(test, feature = "tokio"))]
mod test_pause {
    use super::Error;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    use tokio::sync::oneshot;

    struct Pause {
        entered: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    static PAUSES: OnceLock<Mutex<BTreeMap<PathBuf, Pause>>> = OnceLock::new();

    /// Arms a pause between signed intent and canonical pair acquisition.
    ///
    /// # Errors
    /// Returns an error for poisoned state or an already armed root.
    pub(super) fn arm(root: &Path) -> Result<(oneshot::Receiver<()>, oneshot::Sender<()>), Error> {
        let (entered, observed) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let mut pauses = PAUSES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| Error::Denied)?;
        if pauses.contains_key(root) {
            return Err(Error::Denied);
        }
        pauses.insert(
            root.to_owned(),
            Pause {
                entered,
                resume: resumed,
            },
        );
        Ok((observed, resume))
    }

    /// Waits for a fixture to release an armed post-intent pause.
    ///
    /// # Errors
    /// Returns an error for poisoned state or a closed fixture channel.
    pub(super) async fn after_intent(root: &Path) -> Result<(), Error> {
        let pause = PAUSES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| Error::Denied)?
            .remove(root);
        if let Some(pause) = pause {
            pause.entered.send(()).map_err(|_| Error::Denied)?;
            pause.resume.await.map_err(|_| Error::Denied)?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
impl<F, B, V, C> Repository<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Pauses this actual native fixture after signed intent and before pair acquisition.
    ///
    /// # Errors
    /// Returns an error for poisoned state or an already armed repository.
    pub(crate) fn pause_domain_deletion_after_intent(
        &self,
    ) -> Result<
        (
            tokio::sync::oneshot::Receiver<()>,
            tokio::sync::oneshot::Sender<()>,
        ),
        Error,
    > {
        test_pause::arm(self.coordinator.guard().store().root())
    }
}
