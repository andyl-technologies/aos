//! CSPRNG-backed, publisher-role-separated execution and channel identities.

use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use super::{
    ChannelBinding, PublisherInstanceId, PublisherSession, PublisherSessionError,
    PublisherSessionScope,
};

pub(super) fn generate(
    scope: PublisherSessionScope,
    slots: &[Option<PublisherSession>],
) -> Result<(PublisherInstanceId, ChannelBinding), PublisherSessionError> {
    for _ in 0..4 {
        let mut random = [0_u8; 48];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| PublisherSessionError::EntropyUnavailable)?;
        if random[..32].iter().all(|byte| *byte == 0) {
            continue;
        }
        let mut instance = [0_u8; 16];
        instance.copy_from_slice(&random[32..]);
        instance[6] = (instance[6] & 0x0f) | 0x40;
        instance[8] = (instance[8] & 0x3f) | 0x80;
        let mut hash = Sha256::new();
        hash.update(b"aos-publisher-execution-channel-v1\0");
        hash.update(&random[..32]);
        hash.update(instance);
        hash.update(scope.principal.as_bytes());
        hash.update(scope.node.as_bytes());
        hash.update(scope.project.as_bytes());
        hash.update(scope.cache_resource.as_bytes());
        let instance = PublisherInstanceId::from_bytes(instance);
        let binding = ChannelBinding::new(hash.finalize().into());
        if !slots
            .iter()
            .flatten()
            .any(|session| session.instance == instance || session.binding == binding)
        {
            return Ok((instance, binding));
        }
    }
    Err(PublisherSessionError::IdentityCollision)
}
