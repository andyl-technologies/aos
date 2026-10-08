//! Consumes independently provisioned ONLINE058/059 originals without genesis.
//!
//! Genuine Core origin loans retain the actual parent startup and twelve public
//! credentials. The supplied seed, initialized native journals and written NV
//! are independent inputs, never produced by this consumer. The fixed codecs
//! below authenticate initialization DATA; currentness still requires the same
//! retained main/sidecar writers and the authenticated physical helper.
//!
//! ```text
//! AOSNXG02/version2/reserved | signedSeed640 | checkpoint156 | NV32 | signature64
//! AOSNXS02/version2/reserved | profile532 | emptyAnchor32 | signature64
//! ```

use std::path::Path;

use aos_sandbox::normal_root::{
    ControllerNixSessionFloorOriginV2, NixOwnerPublicSessionFloorOriginV2,
};
use aos_sandbox::production_operation_compiler::NixStartAdmissionErrorV2;
use aos_sandbox_broker::{BrokerAdmissionError, BrokerAuthority};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestBindingV1;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, FixedRoleCredentialErrorV1,
    read_optional_bounded_role_credential_v1,
};
use crate::tpm_nv_custody::{
    FloorCutV1, FloorErrorV1, OnlineFloorCheckpointV1, OnlineFloorProfileV1,
    OnlineFloorRoleV1, online_cut_from_records_v1,
};
use crate::tpm_nv_custody::physical::OriginalOnlinePhysicalAuthDestinationV1;

const INITIALIZATION_BYTES: usize = 904;
const SEED_BYTES: usize = 640;
const ISSUER_NAME: &str = "nix-online-floor-issuer-v1";
const AUTH_NAME: &str = "nix-online-floor-auth-v1";
const GENESIS_NAME: &str = "nix-online-floor-genesis-v1";
const SEED_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.seed.v2\0";
const INITIAL_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.initial-cut.v2\0";

/// Keeps the existing typed Core failure on the same genuine original loan.
pub(crate) enum OnlineOriginV1 {
    Controller {
        original: ControllerNixSessionFloorOriginV2<'static>,
        first_failure: Option<NixStartAdmissionErrorV2>,
    },
    Owner {
        original: NixOwnerPublicSessionFloorOriginV2<'static>,
        first_failure: Option<NixStartAdmissionErrorV2>,
    },
}

impl OnlineOriginV1 {
    pub(crate) fn controller(original: ControllerNixSessionFloorOriginV2<'static>) -> Self {
        Self::Controller { original, first_failure: None }
    }

    pub(crate) fn owner(original: NixOwnerPublicSessionFloorOriginV2<'static>) -> Self {
        Self::Owner { original, first_failure: None }
    }

    pub(crate) const fn role(&self) -> OnlineFloorRoleV1 {
        match self {
            Self::Controller { .. } => OnlineFloorRoleV1::Controller,
            Self::Owner { .. } => OnlineFloorRoleV1::Owner,
        }
    }

    pub(crate) fn failure(&self) -> Option<&NixStartAdmissionErrorV2> {
        match self {
            Self::Controller { first_failure, .. } | Self::Owner { first_failure, .. } => {
                first_failure.as_ref()
            }
        }
    }

    /// Parks the owner's independently verified catalog before its last check.
    pub(crate) fn retain_recipe_catalog_into(
        &mut self,
        target: &mut Option<Vec<aos_sandbox_protocol::nix_build::VerifiedNixRecipeArtifactV2>>,
    ) -> Result<(), FloorErrorV1> {
        match self {
            Self::Owner { original, first_failure } => retain_origin_result(
                first_failure, original.retain_original_recipe_catalog_into(target),
            ),
            Self::Controller { .. } => Err(FloorErrorV1::Provisioning),
        }
    }

    fn retain_admission_anchors(
        &mut self,
        target: &mut Option<(
            aos_sandbox_core::BrokerPlanTrustAnchor,
            aos_sandbox_core::OwnershipLeaseTrustAnchor,
            aos_sandbox_core::NodeId,
        )>,
    ) -> Result<(), FloorErrorV1> {
        match self {
            Self::Controller { original, first_failure } => retain_origin_result(
                first_failure,
                original.retain_original_admission_anchors_into(target),
            ),
            Self::Owner { original, first_failure } => retain_origin_result(
                first_failure,
                original.retain_original_admission_anchors_into(target),
            ),
        }
    }

    pub(crate) fn recheck(&mut self) -> Result<(), FloorErrorV1> {
        match self {
            Self::Controller { original, first_failure } => {
                retain_origin_result(first_failure, original.recheck())
            }
            Self::Owner { original, first_failure } => {
                retain_origin_result(first_failure, original.recheck())
            }
        }
    }

    pub(crate) fn require_service(&mut self) -> Result<(), FloorErrorV1> {
        match self {
            Self::Controller { original, first_failure } => {
                retain_origin_result(first_failure, original.require_physical_service_barrier())
            }
            Self::Owner { original, first_failure } => {
                retain_origin_result(first_failure, original.require_physical_service_barrier())
            }
        }
    }

    pub(crate) fn require_helper(&mut self, process: &PidFd) -> Result<(), FloorErrorV1> {
        match self {
            Self::Controller { original, first_failure } => {
                retain_origin_result(first_failure, original.require_floor_helper(process))
            }
            Self::Owner { original, first_failure } => {
                retain_origin_result(first_failure, original.require_floor_helper(process))
            }
        }
    }

    fn require_profile(&mut self, profile: OnlineFloorProfileV1, issuer: &[u8; 48])
        -> Result<BrokerSessionManifestBindingV1, FloorErrorV1>
    {
        if self.role() != profile.role() || self.failure().is_some() {
            return Err(FloorErrorV1::Provisioning);
        }

        match self {
            Self::Controller { original, first_failure } => {
                let pins = original.fixed_domain_pins();
                let pins = retain_origin_result(first_failure, pins)?;
                require_pins(profile, pins)?;

                let publics = original.public_preimages();
                let publics = retain_origin_result(first_failure, publics)?;
                let bytes = publics.preimages().ok_or(FloorErrorV1::Unavailable)?;
                let binding = require_publics(profile, bytes, issuer)?;
                drop(publics);

                let path = original.profile_path();
                let path = retain_origin_result(first_failure, path)?;
                require_startup_digest(profile, path)?;
                retain_origin_result(first_failure, original.recheck())?;
                Ok(binding)
            }
            Self::Owner { original, first_failure } => {
                let pins = original.fixed_domain_pins();
                let pins = retain_origin_result(first_failure, pins)?;
                require_pins(profile, pins)?;
                let publics = original.public_preimages();
                let publics = retain_origin_result(first_failure, publics)?;
                let binding = require_publics(profile, publics, issuer)?;

                let path = original.profile_path();
                let path = retain_origin_result(first_failure, path)?;
                require_startup_digest(profile, path)?;
                retain_origin_result(first_failure, original.recheck())?;
                Ok(binding)
            }
        }
    }
}

fn retain_origin_result<T>(
    first_failure: &mut Option<NixStartAdmissionErrorV2>,
    result: Result<T, NixStartAdmissionErrorV2>,
) -> Result<T, FloorErrorV1> {
    if first_failure.is_some() {
        return Err(FloorErrorV1::Unavailable);
    }
    match result {
        Ok(value) => Ok(value),
        Err(cause) => {
            *first_failure = Some(cause);
            Err(FloorErrorV1::Unavailable)
        }
    }
}

fn require_pins(
    profile: OnlineFloorProfileV1,
    pins: &aos_sandbox::production_operation_compiler::NixFixedDomainPinsDataV2,
) -> Result<(), FloorErrorV1> {
    if profile.node() != *pins.node().as_bytes()
        || profile.deployment() != *pins.deployment().as_bytes()
        || profile.endpoint() != *pins.endpoint().as_bytes()
        || profile.domain() != *pins.domain().as_bytes()
        || profile.domain_commitment() != *pins.domain_commitment().as_bytes()
        || profile.disclosure() != *pins.disclosure().as_bytes()
    {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn require_publics(
    profile: OnlineFloorProfileV1,
    publics: [&[u8]; 12],
    issuer: &[u8; 48],
) -> Result<BrokerSessionManifestBindingV1, FloorErrorV1> {
    // Preserve the existing twelve-public order. This purpose commitment hashes
    // their individual digests, not a borrowed custody guard or a secret.
    let mut set = Sha256::new();
    for public in publics {
        set.update(Sha256::digest(public));
    }
    if <[u8; 32]>::from(set.finalize()) != profile.public_set_digest() {
        return Err(FloorErrorV1::Provisioning);
    }

    let manifest = crate::manifest::BrokerSessionSecurityManifestV1::decode(publics[2])
        .map_err(|_| FloorErrorV1::Provisioning)?;
    if manifest.key_pins().iter().any(|pin| pin.public_key().as_slice() == &issuer[16..])
        || [0, 5, 7, 10].iter().any(|index| {
            let public = publics[*index];
            public.len() == 48 && public[16..] == issuer[16..]
        })
    {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(manifest.binding())
}

fn require_startup_digest(profile: OnlineFloorProfileV1, path: &Path)
    -> Result<(), FloorErrorV1>
{
    let parent = path.parent().ok_or(FloorErrorV1::Provisioning)?;
    let name = path.file_name().and_then(|name| name.to_str())
        .ok_or(FloorErrorV1::Provisioning)?;
    let bytes = aos_sandbox::immutable_image::read_immutable_image_pin_v1(
        parent, name, 1, 1_048_576,
    ).map_err(|_| FloorErrorV1::Unavailable)?;
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != profile.startup_digest() {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

/// Parks the genuine origin before any separately delivered credential load.
pub(crate) struct OnlineProvisionV1 {
    pub(crate) origin: Option<OnlineOriginV1>,
    issuer: Option<[u8; 48]>,
    auth: Option<Zeroizing<[u8; 32]>>,
    initialization: Option<[u8; INITIALIZATION_BYTES]>,
    profile: Option<OnlineFloorProfileV1>,
    manifest_binding: Option<BrokerSessionManifestBindingV1>,
    anchors: Option<(
        aos_sandbox_core::BrokerPlanTrustAnchor,
        aos_sandbox_core::OwnershipLeaseTrustAnchor,
        aos_sandbox_core::NodeId,
    )>,
    authority_result: Option<Result<BrokerAuthority, BrokerAdmissionError>>,
    first_failure: Option<OnlineProvisionFailureV1>,
    attempted: bool,
}

pub(crate) enum OnlineProvisionFailureV1 {
    Credential(FixedRoleCredentialErrorV1),
    Floor(FloorErrorV1),
    Admission(aos_sandbox_broker::BrokerAdmissionError),
}

impl OnlineProvisionV1 {
    pub(crate) fn new(origin: OnlineOriginV1) -> Self {
        Self {
            origin: Some(origin),
            issuer: None,
            auth: None,
            initialization: None,
            profile: None,
            manifest_binding: None,
            anchors: None,
            authority_result: None,
            first_failure: None,
            attempted: false,
        }
    }

    pub(crate) fn admit(&mut self) -> Result<(), FloorErrorV1> {
        if self.attempted {
            return Err(FloorErrorV1::Unavailable);
        }
        self.attempted = true;
        let result = self.admit_inner();
        if let Err(error) = result {
            self.first_failure.get_or_insert(OnlineProvisionFailureV1::Floor(error));
        }
        result
    }

    fn admit_inner(&mut self) -> Result<(), FloorErrorV1> {
        let origin = self.origin.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        origin.recheck()?;
        let directory = credential_directory(origin.role());

        let issuer = read_credential(directory, ISSUER_NAME, 48, false);
        self.issuer = Some(self.credential_result(issuer)?.try_into()
            .map_err(|_| FloorErrorV1::Provisioning)?);
        let auth = read_credential(directory, AUTH_NAME, 32, true);
        self.auth = Some(Zeroizing::new(self.credential_result(auth)?.try_into()
            .map_err(|_| FloorErrorV1::Provisioning)?));
        let initialization = read_credential(directory, GENESIS_NAME, INITIALIZATION_BYTES, false);
        self.initialization = Some(self.credential_result(initialization)?.try_into()
            .map_err(|_| FloorErrorV1::Provisioning)?);

        let issuer = self.issuer.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let auth = self.auth.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let initialization = self.initialization.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let profile = validate_initialization(initialization, issuer, auth)?;
        self.profile = Some(profile);
        self.manifest_binding = Some(self.origin.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .require_profile(profile, issuer)?);
        self.origin.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .retain_admission_anchors(&mut self.anchors)?;
        let (plan, lease, node) = self.anchors.take().ok_or(FloorErrorV1::Unavailable)?;
        // This is the existing pure checked constructor. Original public files
        // and their fenced startup loan remain resident on provision; the
        // newly decoded DATA anchors move into the same authority engine.
        let result = aos_sandbox_broker::BrokerAuthority::new(
            aos_sandbox_broker::BrokerDomain::Nix,
            plan,
            lease,
            node,
            profile.genesis_id(),
            **auth,
        );
        // Park the actual constructor result before projecting its coarse
        // diagnostic. The payload-free error copy carries no authority.
        self.authority_result = Some(result);
        if let Some(Err(cause)) = self.authority_result.as_ref() {
            self.first_failure.get_or_insert(OnlineProvisionFailureV1::Admission(*cause));
            return Err(FloorErrorV1::Provisioning);
        }
        self.revalidate()
    }

    /// Describes successful occupancy without lending or deriving authority.
    pub(crate) fn has_original_authority(&self) -> bool {
        matches!(self.authority_result.as_ref(), Some(Ok(_)))
    }

    /// Moves only the original successful authority at the final Journal gate.
    pub(crate) fn take_original_authority(&mut self) -> Option<BrokerAuthority> {
        match self.authority_result.take() {
            Some(Ok(authority)) => Some(authority),
            result => {
                self.authority_result = result;
                None
            }
        }
    }

    /// Retains the old transient AUTH copy through the entire physical attempt.
    ///
    /// # Errors
    /// Returns the existing unavailable projection when original AUTH is absent.
    pub(crate) fn prepare_original_physical_input<'provision>(
        &'provision mut self,
        profile: OnlineFloorProfileV1,
    ) -> Result<OnlinePhysicalInputPreparationV1<'provision>, FloorErrorV1> {
        let transient_auth = Zeroizing::new(*self.auth()?);

        Ok(OnlinePhysicalInputPreparationV1 {
            provision: self,
            transient_auth,
            profile,
            phase: OnlinePhysicalInputPhaseV1::Fresh,
        })
    }

    fn credential_result(&mut self, result: Result<Vec<u8>, FixedRoleCredentialErrorV1>)
        -> Result<Vec<u8>, FloorErrorV1>
    {
        match result {
            Ok(bytes) => Ok(bytes),
            Err(cause) => {
                self.first_failure.get_or_insert(OnlineProvisionFailureV1::Credential(cause));
                Err(FloorErrorV1::Unavailable)
            }
        }
    }

    pub(crate) fn profile(&self) -> Result<OnlineFloorProfileV1, FloorErrorV1> {
        self.profile.ok_or(FloorErrorV1::Unavailable)
    }

    pub(crate) fn auth(&self) -> Result<&[u8; 32], FloorErrorV1> {
        self.auth.as_deref().ok_or(FloorErrorV1::Unavailable)
    }

    pub(crate) fn seed(&self) -> Result<&[u8], FloorErrorV1> {
        Ok(&self.initialization.as_ref().ok_or(FloorErrorV1::Unavailable)?[12..652])
    }

    pub(crate) fn seed_key(&self) -> Result<[u8; 24], FloorErrorV1> {
        let mut key = [0; 24];
        key[..8].copy_from_slice(b"AOSNXK01");
        key[8..].copy_from_slice(&self.profile()?.genesis_id());
        Ok(key)
    }

    /// Returns original manifest comparison DATA after fresh owner rechecks.
    pub(crate) fn manifest_binding(&mut self) -> Result<[u8; 32], FloorErrorV1> {
        self.revalidate()?;
        self.manifest_binding.as_ref().map(|binding| *binding.as_bytes())
            .ok_or(FloorErrorV1::Unavailable)
    }

    /// Projects independently authenticated snapshot comparison DATA only.
    pub(crate) fn snapshot_binding(&mut self)
        -> Result<(OnlineFloorProfileV1, [u8; 48]), FloorErrorV1>
    {
        self.revalidate()?;
        Ok((self.profile()?, *self.issuer.as_ref().ok_or(FloorErrorV1::Unavailable)?))
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        if self.first_failure.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        let profile = self.profile()?;
        if let Some(origin) = self.origin.as_mut() {
            origin.recheck()?;
        }
        let directory = credential_directory(profile.role());
        for (name, length, private) in [
            (ISSUER_NAME, 48, false), (AUTH_NAME, 32, true),
            (GENESIS_NAME, INITIALIZATION_BYTES, false),
        ] {
            let result = read_credential(directory, name, length, private);
            let bytes = Zeroizing::new(self.credential_result(result)?);
            let original: &[u8] = match name {
                ISSUER_NAME => self.issuer.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                AUTH_NAME => self.auth()?,
                _ => self.initialization.as_ref().ok_or(FloorErrorV1::Unavailable)?,
            };
            if bytes.as_slice() != original {
                self.first_failure.get_or_insert(OnlineProvisionFailureV1::Floor(FloorErrorV1::Provisioning));
                return Err(FloorErrorV1::Provisioning);
            }
        }
        if let Some(origin) = self.origin.as_mut() {
            origin.recheck()?;
        }
        Ok(())
    }
}

/// Keeps the original provision borrowed until the old admission scope ends.
///
/// This stack borrower never owns the physical carrier or exposes AUTH. The
/// original initialized AUTH remains in provision for later revalidation;
/// its transient copy and the physical owner's copy have distinct lifetimes.
pub(crate) struct OnlinePhysicalInputPreparationV1<'provision> {
    provision: &'provision mut OnlineProvisionV1,
    transient_auth: Zeroizing<[u8; 32]>,
    profile: OnlineFloorProfileV1,
    phase: OnlinePhysicalInputPhaseV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OnlinePhysicalInputPhaseV1 {
    Fresh,
    OriginTaken,
    Transferred,
    Failed,
}

impl OnlinePhysicalInputPreparationV1<'_> {
    /// Supplies only the earlier initialized profile's comparison DATA.
    pub(crate) fn profile(&self) -> OnlineFloorProfileV1 {
        self.profile
    }

    /// Takes the same original only at the third durable tuple operand.
    pub(crate) fn take_original_origin(&mut self) -> Option<OnlineOriginV1> {
        if self.phase != OnlinePhysicalInputPhaseV1::Fresh {
            self.phase = OnlinePhysicalInputPhaseV1::Failed;
            return None;
        }

        self.phase = OnlinePhysicalInputPhaseV1::OriginTaken;
        self.provision.origin.take()
    }

    /// Restores the same missing-tuple original after both locks are restored.
    pub(crate) fn restore_original_origin(&mut self, origin: Option<OnlineOriginV1>) {
        self.provision.origin = origin;
        self.phase = OnlinePhysicalInputPhaseV1::Failed;
    }

    /// Records local completion only after the actual physical owner is parked.
    pub(crate) fn finish_original_transfer(&mut self) {
        self.phase = OnlinePhysicalInputPhaseV1::Transferred;
    }

    /// Fills only the write-only final slot made by the private physical owner.
    pub(crate) fn copy_original_auth_into(
        &self,
        mut destination: OriginalOnlinePhysicalAuthDestinationV1<'_>,
    ) {
        destination.copy_original(&self.transient_auth);
    }
}

fn credential_directory(role: OnlineFloorRoleV1) -> &'static Path {
    Path::new(match role {
        OnlineFloorRoleV1::Controller => "/run/credentials/aos-sandboxd.service",
        OnlineFloorRoleV1::Owner => "/run/credentials/aos-sandbox-nixd.service",
    })
}

fn read_credential(directory: &Path, name: &str, length: usize, private: bool)
    -> Result<Vec<u8>, FixedRoleCredentialErrorV1>
{
    read_optional_bounded_role_credential_v1(
        directory, name, length, length, private, CredentialOwnerPolicyV1::RootOrCurrent,
    )?.ok_or(FixedRoleCredentialErrorV1)
}

fn validate_initialization(
    bytes: &[u8; INITIALIZATION_BYTES], issuer: &[u8; 48], auth: &[u8; 32],
) -> Result<OnlineFloorProfileV1, FloorErrorV1> {
    if bytes[..12] != *b"AOSNXG02\0\x02\0\0"
        || bytes[12..24] != *b"AOSNXS02\0\x02\0\0"
        || issuer[..16] == [0; 16] || issuer[16..] == [0; 32] || *auth == [0; 32]
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let profile = OnlineFloorProfileV1::decode(&bytes[24..556])?;
    if profile.issuer_digest() != <[u8; 32]>::from(Sha256::digest(issuer))
        || profile.auth_digest() != <[u8; 32]>::from(Sha256::digest(auth))
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let public: [u8; 32] = issuer[16..].try_into().map_err(|_| FloorErrorV1::Provisioning)?;
    let verifier = VerifyingKey::from_bytes(&public).map_err(|_| FloorErrorV1::Provisioning)?;
    let seed_signature = Signature::from_slice(&bytes[588..652])
        .map_err(|_| FloorErrorV1::Provisioning)?;
    let mut seed_message = Vec::with_capacity(SEED_DOMAIN.len() + 576);
    seed_message.extend_from_slice(SEED_DOMAIN);
    seed_message.extend_from_slice(&bytes[12..588]);
    verifier.verify_strict(&seed_message, &seed_signature)
        .map_err(|_| FloorErrorV1::Provisioning)?;
    let initial_signature = Signature::from_slice(&bytes[840..])
        .map_err(|_| FloorErrorV1::Provisioning)?;
    let mut initial_message = Vec::with_capacity(INITIAL_DOMAIN.len() + 840);
    initial_message.extend_from_slice(INITIAL_DOMAIN);
    initial_message.extend_from_slice(&bytes[..840]);
    verifier.verify_strict(&initial_message, &initial_signature)
        .map_err(|_| FloorErrorV1::Provisioning)?;

    let empty = online_cut_from_records_v1(profile, 1, std::iter::empty())?;
    if bytes[556..588] != empty.head() {
        return Err(FloorErrorV1::Provisioning);
    }
    let mut key = [0; 24];
    key[..8].copy_from_slice(b"AOSNXK01");
    key[8..].copy_from_slice(&profile.genesis_id());
    let initialized = online_cut_from_records_v1(
        profile, 4, [(key.as_slice(), &bytes[12..12 + SEED_BYTES])],
    )?;
    let checkpoint = OnlineFloorCheckpointV1::decode(&bytes[652..808])?;
    checkpoint.require_profile(profile)?;
    if checkpoint.ordinal() != 1 || checkpoint.cut() != initialized
        || checkpoint.encode()[92..] != [0; 64] || bytes[808..840] != checkpoint.nv_value()
        || bytes[808..840] == [0; 32]
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let _complete_initial_cut: FloorCutV1 = initialized;
    Ok(profile)
}
