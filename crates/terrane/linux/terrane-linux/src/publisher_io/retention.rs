//! Prepares fallible incarnation custody before native publication effects.

use super::*;
use terrane_sdk::host::publication::RetainedPublishedObject;

pub(super) struct PreparedRetention {
    key: NativeBodyKey,
    claim: Arc<PublicationClaim>,
    token: [u8; 32],
    slot: Option<usize>,
}

impl CommandOwner {
    pub(super) async fn prepare_retention(
        &mut self,
        claim: Arc<PublicationClaim>,
    ) -> io::Result<PreparedRetention> {
        self.confinement.check_current()?;
        let key = NativeBodyKey::Sealed {
            descriptor: claim.descriptor().clone(),
        };
        // This owner excludes every other sealed writer throughout preflight
        // and the engine. Canonical inode identity cannot change between these
        // checks and registration except through this same accepted command.
        let canonical = self.kernel(|native| native.existing_canonical_identity(&claim))?;
        let slot = self
            .bodies
            .iter()
            .position(|body| body.key == key && body.location == Location::Canonical);
        let previous_token = match (slot, canonical) {
            (Some(index), Some(canonical)) => {
                let previous = self.bodies[index].file.metadata()?;
                ((previous.dev(), previous.ino()) == canonical).then_some(self.bodies[index].token)
            }
            _ => None,
        };
        if slot.is_none() && self.bodies.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "publisher incarnation budget exhausted",
            ));
        }
        if slot.is_none() {
            self.bodies.try_reserve(1).map_err(io::Error::other)?;
        }
        let token = match previous_token {
            Some(token) => token,
            None => TokioLocalFs
                .random_bytes(32)
                .await?
                .try_into()
                .map_err(|_| io::Error::other("invalid native random length"))?,
        };
        Ok(PreparedRetention {
            key,
            claim,
            token,
            slot,
        })
    }

    pub(super) fn commit_retention(
        &mut self,
        prepared: PreparedRetention,
        object: RetainedPublishedObject<File>,
        manifest: Option<Arc<NativeManifestWitness>>,
    ) -> NativeCommandResult {
        let (object, file) = object.into_parts();
        let PreparedRetention {
            key,
            claim,
            token,
            slot,
        } = prepared;
        let body = RetainedBody {
            key,
            claim: Some(claim),
            token,
            file,
            location: Location::Canonical,
            encoded: None,
            manifest,
        };
        // Only the owned engine ran since preparation; it cannot modify this
        // table. Replacement uses that stable slot, while insertion consumes
        // capacity reserved before the first publication/adoption effect.
        match slot {
            Some(index) => self.bodies[index] = body,
            None => self.bodies.push(body),
        }
        NativeCommandResult::Published {
            object: NativePublishedObject { object },
            incarnation: NativeBodyIncarnation(token),
        }
    }
}
