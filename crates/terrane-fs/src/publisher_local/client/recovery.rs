//! Exchanges bounded recovery names without inferring content or pin authority.
//!
//! Private observations bind actual replies to the client, retained layout and
//! drain epoch. Encoded bodies remain unverified candidates for the concrete
//! cache owner to reconstruct and authenticate before completing recovery.

use std::{fs::File, sync::Arc};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use terrane::host::{cache::HostReadLocation, publication::PublicationClaim};

use super::super::wire::{BodyKey, BodyKind, Claim, Operation};
use super::{Client, Error, RequestPayload, State, invalidate, receipt};
use crate::host_cache::NativeHostLayout;

/// A consumed connection-and-drain-scoped inventory continuation, never authority.
pub(crate) struct InventoryCursor {
    client: [u8; 16],
    epoch: u64,
    bytes: Vec<u8>,
}

/// Contains at most 64 unverified native key names and an owned continuation.
pub(crate) struct InventoryPage {
    /// Registered names requiring actual cache reconstruction and verification.
    pub(crate) keys: Vec<BodyKey>,
    /// A single-use continuation bound to this client's current drain epoch.
    pub(crate) next_cursor: Option<InventoryCursor>,
}

/// Names an actual publisher-retained inode without proving its content.
pub(crate) struct BodyIncarnationObservation<L: HostReadLocation> {
    key: BodyKey,
    token: [u8; 32],
    client: [u8; 16],
    epoch: u64,
    layout: Arc<NativeHostLayout<L>>,
}

impl<L: HostReadLocation> BodyIncarnationObservation<L> {
    /// Borrows the checked registered name, which grants no content authority.
    pub(crate) fn key(&self) -> &BodyKey {
        &self.key
    }

    /// Builds only this actual connection/epoch observation's registered payload.
    ///
    /// # Errors
    /// Refuses another actual client, root, epoch or producer-selected key.
    #[cfg(feature = "tokio")]
    pub(super) fn checked_payload(
        &self,
        client: &Client<L>,
        state: &State,
        expected: &BodyKey,
    ) -> Result<RequestPayload, Error> {
        if self.client != client.cache_incarnation
            || self.epoch != state.recovery_epoch
            || !Arc::ptr_eq(&self.layout, &client.layout)
            || &self.key != expected
        {
            return Err(Error::Invalid(
                "inode observation belongs to another command context",
            ));
        }
        Ok(RequestPayload {
            body: Some(self.key.clone()),
            incarnation: self.token.to_vec(),
            ..Default::default()
        })
    }
}

/// Retains an encoded inode candidate without hash, service or pin authority.
pub(crate) struct UnverifiedBody<L: HostReadLocation> {
    file: File,
    _key: BodyKey,
    _layout: Arc<NativeHostLayout<L>>,
}

impl<L: HostReadLocation> UnverifiedBody<L> {
    /// Borrows the readonly candidate for actual owner-side byte verification.
    pub(crate) fn handle(&self) -> &File {
        &self.file
    }
}

/// Separates genuinely verified inline data from unverified encoded candidates.
pub(crate) enum RecoveryBody<L: HostReadLocation> {
    /// Contains independently verified inline content and a lifecycle name.
    Sealed {
        /// The actual readonly file, kernel seal, claim and retained root.
        object: Box<super::PeerPublishedObject<L>>,
        /// The actual publisher-issued inode observation for this drain epoch.
        observation: BodyIncarnationObservation<L>,
    },
    /// Contains no decoded-content, service, manifest or pin proof.
    Encoded {
        /// The retained readonly candidate requiring actual byte verification.
        body: UnverifiedBody<L>,
        /// The actual publisher-issued inode observation for this drain epoch.
        observation: BodyIncarnationObservation<L>,
    },
}

impl<L: HostReadLocation> Client<L> {
    /// Retrieves one bounded inventory page under the actual drain barrier.
    ///
    /// # Errors
    ///
    /// Rejects undrained state, another client/connection/drain cursor, failed
    /// transport or a registered publisher error. Names prove no content facts.
    pub(crate) fn inventory(
        &self,
        cursor: Option<InventoryCursor>,
    ) -> Result<InventoryPage, Error> {
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let bytes = match cursor {
            Some(cursor) => {
                if cursor.client != self.cache_incarnation || cursor.epoch != state.recovery_epoch {
                    return Err(Error::Invalid(
                        "inventory cursor belongs to another recovery connection",
                    ));
                }
                cursor.bytes
            }
            None => Vec::new(),
        };
        let received = self.exchange_payload(
            &mut state,
            Operation::Inventory,
            RequestPayload {
                cursor: bytes,
                ..Default::default()
            },
        )?;
        let next_cursor = if received.packet.inventory_cursor.is_empty() {
            None
        } else {
            Some(InventoryCursor {
                client: self.cache_incarnation,
                epoch: state.recovery_epoch,
                bytes: received.packet.inventory_cursor,
            })
        };
        Ok(InventoryPage {
            keys: received.packet.inventory,
            next_cursor,
        })
    }

    /// Retains a pending inode's lifecycle name without receiving a file or seal.
    ///
    /// # Errors
    ///
    /// Rejects undrained state, invalid names, unavailable pending custody and
    /// transport failures. A successful observation is not serving authority.
    pub(crate) fn inspect_pending(
        &self,
        key: BodyKey,
    ) -> Result<BodyIncarnationObservation<L>, Error> {
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let received = self.exchange_payload(
            &mut state,
            Operation::InspectPending,
            RequestPayload {
                body: Some(key.clone()),
                ..Default::default()
            },
        )?;
        self.observation(&state, key, &received.packet.body_incarnation)
    }

    /// Inspects actual backing custody while preserving encoded uncertainty.
    ///
    /// Sealed inspection requires an inline claim revalidated under the actual
    /// layout profile and independently verified against the returned bytes.
    /// Manifest inspection requires its separate durable retention bridge.
    ///
    /// # Errors
    ///
    /// Rejects undrained state, wrong keys or claims, missing actual custody,
    /// wrong descriptor ownership/device/access, seal or inline identity
    /// mismatches, stale roots and failed publisher exchanges.
    pub(crate) fn inspect_body(
        &self,
        key: BodyKey,
        inline: Option<PublicationClaim>,
    ) -> Result<RecoveryBody<L>, Error> {
        let sealed = key.kind == BodyKind::Sealed as i32;
        let claim = match (sealed, inline) {
            (true, Some(claim)) => Some(self.inline_claim(claim)?),
            (false, None) => None,
            _ => {
                return Err(Error::Invalid(
                    "sealed inspection requires inline claim only",
                ));
            }
        };
        let wire_claim = claim.as_ref().map(|claim| Claim {
            descriptor: claim.descriptor().encode(),
            chunk_profile: self.config.chunk_profile_name.clone(),
            plaintext_size: claim.plaintext_size(),
            ..Default::default()
        });
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let received = self.exchange_payload(
            &mut state,
            Operation::InspectBody,
            RequestPayload {
                claim: wire_claim,
                body: Some(key.clone()),
                ..Default::default()
            },
        )?;
        let observation =
            self.observation(&state, key.clone(), &received.packet.body_incarnation)?;
        let result = match claim {
            Some(claim) => receipt::published(
                received,
                self.layout.clone(),
                self.config.identities.publish_uid,
                claim,
            )
            .map(|object| RecoveryBody::Sealed {
                object: Box::new(object),
                observation,
            }),
            None => self
                .unverified_body(key, received.files)
                .map(|body| RecoveryBody::Encoded { body, observation }),
        };
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

    /// Restores the exact observed pending inode without granting serving proof.
    ///
    /// # Errors
    ///
    /// Rejects stale or foreign observations, undrained state and failed native
    /// exchanges. Restored sealed data still requires actual canonical adoption.
    pub(crate) fn restore(&self, observation: &BodyIncarnationObservation<L>) -> Result<(), Error> {
        self.lifecycle(Operation::Restore, observation)
    }

    fn lifecycle(
        &self,
        operation: Operation,
        observation: &BodyIncarnationObservation<L>,
    ) -> Result<(), Error> {
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        if observation.client != self.cache_incarnation
            || observation.epoch != state.recovery_epoch
            || !Arc::ptr_eq(&observation.layout, &self.layout)
        {
            return Err(Error::Invalid(
                "inode observation belongs to another recovery connection",
            ));
        }
        self.exchange_payload(
            &mut state,
            operation,
            RequestPayload {
                body: Some(observation.key.clone()),
                incarnation: observation.token.to_vec(),
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// Captures a lifecycle name directly from the currently locked peer response.
    ///
    /// # Errors
    /// Rejects a token whose width differs from the registered 32 bytes.
    pub(super) fn observation(
        &self,
        state: &State,
        key: BodyKey,
        token: &[u8],
    ) -> Result<BodyIncarnationObservation<L>, Error> {
        let token = token
            .try_into()
            .map_err(|_| Error::Invalid("native body incarnation width"))?;
        Ok(BodyIncarnationObservation {
            key,
            token,
            client: self.cache_incarnation,
            epoch: state.recovery_epoch,
            layout: self.layout.clone(),
        })
    }

    /// Correlates the same-response lifecycle name with its verified sealed body.
    ///
    /// This checks current canonical response custody, not a prior scanned inode.
    ///
    /// # Errors
    /// Rejects a stale original barrier or a different key, token, root or session.
    pub(super) fn correlate_sealed_response(
        &self,
        state: &State,
        context: &super::PublisherRecoveryContext<L>,
        observation: &BodyIncarnationObservation<L>,
        body: &super::PeerPublishedObject<L>,
    ) -> Result<(), Error> {
        self.require_recovery_context(state, context)?;
        if observation.client != self.cache_incarnation
            || observation.epoch != state.recovery_epoch
            || !Arc::ptr_eq(&observation.layout, &self.layout)
            || !Arc::ptr_eq(body.layout(), &self.layout)
            || observation.key
                != (BodyKey {
                    kind: BodyKind::Sealed as i32,
                    descriptor: body.claim().descriptor().encode(),
                    ..Default::default()
                })
            || &observation.token != body.incarnation()
            || body.claim().domain() != self.layout.layout().domain()
        {
            return Err(Error::Invalid("sealed response lifecycle correlation"));
        }
        Ok(())
    }

    fn unverified_body(
        &self,
        key: BodyKey,
        mut files: Vec<File>,
    ) -> Result<UnverifiedBody<L>, Error> {
        self.layout.recheck()?;
        if files.len() != 1 {
            return Err(Error::Invalid("unsealed inspection descriptor count"));
        }
        let file = files
            .pop()
            .ok_or(Error::Invalid("missing unsealed inode"))?;
        let label = match BodyKind::try_from(key.kind) {
            Ok(BodyKind::Chunk) => "chunks",
            Ok(BodyKind::Pack) => "objects",
            _ => return Err(Error::Invalid("unsealed body kind")),
        };
        let directory = rustix::fs::openat2(
            rustix::fs::CWD,
            self.layout.layout().root().join(label),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?;
        let class = rustix::fs::fstat(&directory)?;
        let stat = rustix::fs::fstat(&file)?;
        let flags = rustix::fs::fcntl_getfl(&file)?;
        let expected_project = crate::host_quota::NativeProject::inspect(&File::from(directory))?;
        let actual_project = crate::host_quota::NativeProject::inspect(&file)?;
        if self.layout.directory_binding(label)? != (class.st_dev, class.st_ino)
            || stat.st_dev != self.layout.directory_binding("layout-root")?.0
            || stat.st_uid != class.st_uid
            || actual_project.project_id != expected_project.project_id
            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
        {
            return Err(Error::Invalid(
                "unsealed backing access, device or owner mismatch",
            ));
        }
        self.layout.recheck()?;
        Ok(UnverifiedBody {
            file,
            _key: key,
            _layout: self.layout.clone(),
        })
    }
}
