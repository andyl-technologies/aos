//! Selects complete sealed files from actual acknowledged recovery custody.
//!
//! Whole-file selection deliberately does not use the chunk residence map:
//! another assembled object may supply every residence for the same chunks.

use super::{invalid, matches_identity};
use crate::{
    host_cache::{
        owner::{
            consumer::state as policy,
            publication::residence,
            retention::{Custody, NativeOwnerExecutor},
        },
        recovery_inspection::VerifiedRecoveryManifest,
    },
    publisher_local::client::{PeerPublishedObject, PublisherRunningContext},
};
use std::{io, sync::Arc};
use terrane_format::identity::{Identity, IdentityKind};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains the original adopted body and its acknowledged recovery provenance.
pub(super) struct RecoveredOrigin {
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    running: Arc<PublisherRunningContext>,
    manifest: Option<Arc<VerifiedRecoveryManifest>>,
}

impl RecoveredOrigin {
    /// Selects only actual sources already reconciled before acknowledged Resume.
    ///
    /// # Errors
    /// Refuses absent actual recovery sources, unsupported identities, stale
    /// snapshot custody or lost original metadata and bootstrap funding.
    pub(super) fn select(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        identity: &Identity,
        running: Arc<PublisherRunningContext>,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        let source = match identity.kind() {
            IdentityKind::Chunk => {
                let mut selected = None;
                for body in executor.inline_registry() {
                    if matches_identity(body.claim().descriptor(), identity)? {
                        selected = Some(Self {
                            body: Arc::clone(body),
                            running,
                            manifest: None,
                        });
                        break;
                    }
                }
                selected
            }
            IdentityKind::Manifest => {
                let mut selected = None;
                for manifest in executor.verified_manifests() {
                    if matches_identity(manifest.claim().descriptor(), identity)? {
                        selected = Some(Self {
                            body: manifest.body().retained().body_arc(),
                            running,
                            manifest: Some(Arc::clone(manifest)),
                        });
                        break;
                    }
                }
                selected
            }
            _ => return Err(invalid("recovered whole file requires a content identity")),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "verified recovered whole file absent",
            )
        })?;
        source.check_registration(owner)?;
        Ok(source)
    }

    /// Borrows this original recovered body without reopening a pathname.
    pub(super) fn body(&self) -> &Arc<PeerPublishedObject<HostDomainLocation>> {
        &self.body
    }

    /// Checks original Running custody without repeating obsolete Drain predicates.
    ///
    /// # Errors
    /// Refuses stale policy, another physical layout or session, lost bootstrap
    /// funding and a changed independently verified manifest body/metadata pair.
    pub(super) fn check_registration(&self, owner: &Custody) -> io::Result<()> {
        residence::check_snapshot(owner)?;
        policy::check_bootstrap(owner, &self.running)?;
        if owner.faulted
            || owner.recovery_required
            || !Arc::ptr_eq(self.body.layout(), owner.preparation.layout())
            || self.body.claim().domain() != self.body.layout().layout().domain()
        {
            return Err(invalid(
                "recovered whole file lost original physical custody",
            ));
        }

        if let Some(manifest) = &self.manifest {
            let retained = manifest.body().retained();
            let claim = manifest.claim();
            if !Arc::ptr_eq(&retained.body_arc(), &self.body)
                || claim.manifest().is_none()
                || self.body.claim().descriptor() != claim.descriptor()
                || self.body.claim().domain() != claim.domain()
                || self.body.claim().canonical_manifest() != claim.canonical_manifest()
            {
                return Err(invalid(
                    "recovered whole file changed its original manifest pair",
                ));
            }
            retained.backing().check_recovery_registration(owner)?;
        } else if self.body.claim().manifest().is_some() {
            return Err(invalid(
                "recovered inline file has another original content kind",
            ));
        }
        Ok(())
    }
}
