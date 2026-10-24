//! Assembles normal055 inputs only beside the genuine retained Boot Source.
//!
//! The fixed credential reader remains the sole native engine. Signed normal
//! purpose and complete genesis bytes are DATA custody; this assembly grants
//! no signature, journal append, fresh NV, target generation or publication.

use super::*;

pub(in crate::runtime_deployment) struct BootGenesisAssemblyV1<'startup> {
    startup: &'startup super::super::RuntimeBootPreparationStartupOriginalV1,
    exact: Vec<u8>,
    provisioner: VerifyingKey,
    signer: SigningKey,
    genesis: DeploymentGenesisV1,
    purpose: SignedBootPreparationPurposeDataV1,
}

impl<'startup> BootGenesisAssemblyV1<'startup> {
    pub(in crate::runtime_deployment) fn decode(
        startup: &'startup super::super::RuntimeBootPreparationStartupOriginalV1,
        credentials: &RuntimeDeploymentCredentialCustodyV2,
    ) -> Result<Self, NvCustodyErrorV1> {
        startup
            .require_current_v1()
            .map_err(|_| NvCustodyErrorV1::Provisioning)?;
        let [signed, provisioner, seed, auth, purpose] =
            credentials.ready().ok_or(NvCustodyErrorV1::Provisioning)?;
        let provisioner = VerifyingKey::from_bytes(
            &provisioner
                .try_into()
                .map_err(|_| NvCustodyErrorV1::Encoding)?,
        )
        .map_err(|_| NvCustodyErrorV1::Provisioning)?;
        if provisioner.is_weak() || seed == [0; 32] || auth == [0; 32] || seed == auth {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(seed);
        let signer = SigningKey::from_bytes(&secret);
        let genesis = decode_signed(signed, &provisioner)?;
        let original = PublisherStartupOriginalRefV3::Boot(startup);
        require_bindings(
            &genesis,
            original.profile_digest()?,
            original.canonical_policy_digest()?,
        )?;
        if genesis.signer != signer.verifying_key().to_bytes()
            || genesis.signer == provisioner.to_bytes()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        let purpose = SignedBootPreparationPurposeDataV1::verify_v1(
            purpose,
            &signed.try_into().map_err(|_| NvCustodyErrorV1::Encoding)?,
            &genesis,
            &provisioner,
        )
        .map_err(|_| NvCustodyErrorV1::Provisioning)?;
        require_boot_contracts(startup, &genesis, &purpose)?;

        let mut exact = Vec::new();
        exact
            .try_reserve_exact(BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1)
            .map_err(|_| NvCustodyErrorV1::Unavailable)?;
        exact.extend_from_slice(signed);
        exact.extend_from_slice(purpose.bytes_v1());
        Ok(Self {
            startup,
            exact,
            provisioner,
            signer,
            genesis,
            purpose,
        })
    }

    pub(in crate::runtime_deployment) fn into_original(
        self,
        credentials: RuntimeDeploymentCredentialCustodyV2,
    ) -> VerifiedDeploymentGenesisV1<'startup> {
        VerifiedDeploymentGenesisV1 {
            startup: PublisherStartupOriginalRefV3::Boot(self.startup),
            exact: self.exact,
            provisioner: self.provisioner,
            signer: self.signer,
            genesis: self.genesis,
            canary: None,
            boot: Some(BootGenesisCustodyV1 {
                credentials: Mutex::new(credentials),
                purpose: self.purpose,
                journal_receiving: std::cell::RefCell::new(crate::journal::runtime_deployment_receiving::BootJournalReceivingArchiveV1::new()),
            }),
        }
    }
}
