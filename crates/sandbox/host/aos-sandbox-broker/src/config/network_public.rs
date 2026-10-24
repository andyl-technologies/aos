//! Captures the six original public Network pins donated by the live Netd.
//!
//! Native Source authentication and the complete same-F quote precede entry.
//! The fixed credential reader and public anchor materializer are shared with
//! ordinary configuration. No journal key, MAC verifier or effect issuer exists
//! in this receiver.

use std::error::Error;

use super::materialization::PublicAnchorMaterializationV2;
use super::receiving::{ConfigurationCredentialOriginalV1, take_public_credentials_v2};
use super::*;

/// Retains six donated public descriptors and their actual native read prefix.
#[must_use = "retain original credentials and the first native cause through all posts"]
pub struct NetworkPublicCredentialsOriginalV2 {
    credentials: [ConfigurationCredentialOriginalV1; 6],
    anchors: PublicAnchorMaterializationV2,
    entered: bool,
    node: Option<[u8; 16]>,
    result: Option<Result<(), BrokerAuthorityConfigError>>,
    reentry: Option<BrokerAuthorityConfigError>,
    taken: bool,
}

impl NetworkPublicCredentialsOriginalV2 {
    /// Creates inert destinations before the original parent pays their quote.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: std::array::from_fn(|_| ConfigurationCredentialOriginalV1::new()),
            anchors: PublicAnchorMaterializationV2::new(),
            entered: false,
            node: None,
            result: None,
            reentry: None,
            taken: false,
        }
    }

    /// Quotes the existing complete configuration recipe conservatively.
    ///
    /// No secret is received or read. The unchanged full configuration bound
    /// covers public policy models, exact repeated readers and failed duplicate
    /// custody; compiled additional owner space is charged independently.
    ///
    /// # Errors
    /// Refuses checked accounting overflow.
    pub fn receiving_demand_v2()
    -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D};
        let base = ProtectedBrokerAuthorityConfiguration::receiving_demand_v1()?;
        let owner = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            }
        })?;
        base.checked_add(aos_sandbox_model::ResourceVector::ZERO.with(D::MemoryBytes, owner))
    }

    /// Captures the exact six original rights in the closed public-role order.
    ///
    /// All rights become resident before the first read. Native Source record
    /// authentication is a separate mandatory gate in the Network receiver.
    /// The expected evidence comes from the same original Netd configuration.
    ///
    /// # Errors
    /// Refuses reentry, changed inode/content metadata, an invalid fixed role,
    /// policy/key mismatch, zero node or any actual native read failure.
    pub fn capture_once_v2(
        &mut self,
        files: [OwnedFd; 6],
        expected: [ProtectedBrokerPublicCredentialSnapshot; 6],
    ) -> Result<(), BrokerAuthorityConfigError> {
        if self.entered {
            self.reentry
                .get_or_insert(BrokerAuthorityConfigError::Invalid(
                    "public credential reentry",
                ));
            return Err(BrokerAuthorityConfigError::Invalid(
                "public credential reentry",
            ));
        }
        self.entered = true;
        for (destination, file) in self.credentials.iter_mut().zip(files) {
            destination.opened = Some(Ok(Some(file)));
        }
        self.result = Some(self.capture_inner(expected));
        match self.result.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(BrokerAuthorityConfigError::Invalid(
                "Network public credentials",
            )),
        }
    }

    fn capture_inner(
        &mut self,
        expected: [ProtectedBrokerPublicCredentialSnapshot; 6],
    ) -> Result<(), BrokerAuthorityConfigError> {
        let recipes = [
            (PLAN_POLICY_FILE, MAXIMUM_POLICY_BYTES, None),
            (PLAN_PUBLIC_KEY_FILE, 32, Some(32)),
            (PLAN_REVOCATION_SCOPE_FILE, 16, Some(16)),
            (LEASE_POLICY_FILE, MAXIMUM_POLICY_BYTES, None),
            (LEASE_PUBLIC_KEY_FILE, 32, Some(32)),
            (NODE_ID_FILE, 16, Some(16)),
        ];
        for ((original, (name, maximum, exact)), expected) in
            self.credentials.iter_mut().zip(recipes).zip(expected)
        {
            original.read_donated_once_v2(name, maximum, exact, 0)?;
            let snapshot = original
                .comparison
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|snapshot| *snapshot)
                .ok_or(BrokerAuthorityConfigError::Invalid(name))?;
            if snapshot.public() != expected {
                return Err(BrokerAuthorityConfigError::Invalid(name));
            }
        }
        let policy = |index: usize, name| {
            self.credentials[index]
                .bytes
                .as_ref()
                .map(|bytes| bytes.as_slice())
                .ok_or(BrokerAuthorityConfigError::Invalid(name))
        };
        let node = self.credentials[5].exact(NODE_ID_FILE)?;
        if node == [0; 16] {
            return Err(BrokerAuthorityConfigError::Invalid(NODE_ID_FILE));
        }
        let plan_key = self.credentials[1].exact(PLAN_PUBLIC_KEY_FILE)?;
        let scope = self.credentials[2].exact(PLAN_REVOCATION_SCOPE_FILE)?;
        let lease_key = self.credentials[4].exact(LEASE_PUBLIC_KEY_FILE)?;
        self.anchors.run_once(
            policy(0, PLAN_POLICY_FILE)?,
            &plan_key,
            scope,
            policy(3, LEASE_POLICY_FILE)?,
            &lease_key,
        )?;
        self.node = Some(node);
        Ok(())
    }

    /// Moves the genuine public verifier and complete original credential set.
    #[must_use]
    pub fn take_completed_once_v2(
        &mut self,
    ) -> Option<(
        crate::NetworkPublicVerifierV2,
        ProtectedBrokerPublicCredentials,
    )> {
        if self.taken || self.reentry.is_some() || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        let node = self.node?;
        let credentials = take_public_credentials_v2(&mut self.credentials)?;
        let Some(verifier) = self.anchors.take_verifier_once(node) else {
            for (destination, credential) in
                self.credentials.iter_mut().zip(credentials.credentials)
            {
                destination.opened = Some(Ok(Some(credential.descriptor)));
            }
            return None;
        };
        self.taken = true;
        Some((verifier, credentials))
    }

    /// Borrows the first reached native or typed construction failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.credentials
            .iter()
            .find_map(ConfigurationCredentialOriginalV1::failure)
            .or_else(|| self.anchors.failure())
            .or_else(|| {
                self.result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.reentry.as_ref().map(|error| error as _))
    }
}

impl Default for NetworkPublicCredentialsOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> [OwnedFd; 6] {
        std::array::from_fn(|_| tempfile::tempfile().unwrap().into())
    }

    fn evidence() -> [ProtectedBrokerPublicCredentialSnapshot; 6] {
        std::array::from_fn(|_| {
            ProtectedBrokerPublicCredentialSnapshot::decode_network_handoff_data_v2(&[0; 56])
                .unwrap()
        })
    }

    #[test]
    fn rejected_first_role_and_reentry_keep_every_original_donated_file() {
        let files = files();
        let inodes: [u64; 6] = std::array::from_fn(|index| fstat(&files[index]).unwrap().st_ino);
        let mut original = NetworkPublicCredentialsOriginalV2::new();

        assert!(original.capture_once_v2(files, evidence()).is_err());
        assert!(original.failure().is_some());
        assert!(original.take_completed_once_v2().is_none());
        assert!(original.capture_once_v2(self::files(), evidence()).is_err());

        for (slot, inode) in original.credentials.iter().zip(inodes) {
            let Some(Ok(Some(file))) = slot.opened.as_ref() else {
                panic!("an original donation was lost after failed capture or reentry");
            };
            assert_eq!(fstat(file).unwrap().st_ino, inode);
        }
    }
}
