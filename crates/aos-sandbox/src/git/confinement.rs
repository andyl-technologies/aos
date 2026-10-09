//! Dormant environment/Git key, writer, and MAC confinement declaration.
//!
//! This table is an auditable source contract, not an installed SELinux
//! module. Production capability advertisement must remain unavailable until
//! an enforcing policy is compiled from an equivalent declaration and proven
//! on the selected kernel and labeled root.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Names one mutually confined environment or Git process role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SandboxSourceSecurityDomainV1 {
    /// Reconciles controller state but owns no effect or signing key.
    Controller = 1,
    /// Writes fixed environment capability and presentation evidence.
    EnvironmentAuthorityWriter = 2,
    /// Owns one trust-domain Nix database and constrained build execution.
    NixStoreOwner = 3,
    /// Seals build receipts and output observations without build authority.
    NixObservationWriter = 4,
    /// Validates Git object graphs without mutable repository authority.
    GitGraphValidator = 5,
    /// Terminates authenticated protocol-v2 sessions without pack publication keys.
    GitSmartGateway = 6,
    /// Owns receive-pack quarantine but cannot publish refs directly.
    GitQuarantineWriter = 7,
    /// Publishes validated refs and immutable packs without accepting network input.
    GitPublisher = 8,
    /// Seals smart-exchange observations without repository write authority.
    GitObservationWriter = 9,
    /// Writes authenticated smart-session records without serving them.
    GitSessionWriter = 10,
    /// Publishes verified NARs without build or client-session authority.
    NixCachePublisher = 11,
}

impl SandboxSourceSecurityDomainV1 {
    /// Returns the stable SELinux type required of an eventual compiled policy.
    #[must_use]
    pub const fn selinux_type(self) -> &'static str {
        match self {
            Self::Controller => "aos_sandbox_controller_t",
            Self::EnvironmentAuthorityWriter => "aos_sandbox_environment_authority_t",
            Self::NixStoreOwner => "aos_sandbox_nix_store_owner_t",
            Self::NixObservationWriter => "aos_sandbox_nix_observation_t",
            Self::GitGraphValidator => "aos_sandbox_git_validator_t",
            Self::GitSmartGateway => "aos_sandbox_git_gateway_t",
            Self::GitQuarantineWriter => "aos_sandbox_git_quarantine_t",
            Self::GitPublisher => "aos_sandbox_git_publisher_t",
            Self::GitObservationWriter => "aos_sandbox_git_observation_t",
            Self::GitSessionWriter => "aos_sandbox_git_session_writer_t",
            Self::NixCachePublisher => "aos_sandbox_nix_cache_publisher_t",
        }
    }
}

/// Declares process-level confinement independent of file allow rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxSourceProcessConfinementV1 {
    /// Process role covered by the declaration.
    pub domain: SandboxSourceSecurityDomainV1,
    /// Whether the domain may accept untrusted network traffic.
    pub network_ingress: bool,
    /// Whether the domain may execute the fixed Nix effect backend.
    pub execute_nix: bool,
    /// Whether the domain may execute a fixed Git implementation.
    pub execute_git: bool,
    /// Linux capability bit set; v1 requires this to remain empty.
    pub linux_capabilities: u64,
    /// Whether general procfs reads are permitted; v1 requires false.
    pub general_procfs: bool,
    /// Whether mount operations are permitted; v1 requires false.
    pub mount_authority: bool,
    /// Whether system-manager mutation is permitted; v1 requires false.
    pub system_manager_authority: bool,
}

/// Complete process-domain confinement declarations for the dormant model.
pub const SANDBOX_SOURCE_PROCESS_CONFINEMENT_V1: [SandboxSourceProcessConfinementV1; 11] = [
    process(
        SandboxSourceSecurityDomainV1::Controller,
        false,
        false,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::EnvironmentAuthorityWriter,
        false,
        false,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::NixStoreOwner,
        false,
        true,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::NixObservationWriter,
        false,
        false,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitGraphValidator,
        false,
        false,
        true,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitSmartGateway,
        true,
        false,
        true,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitQuarantineWriter,
        false,
        false,
        true,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitPublisher,
        false,
        false,
        true,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitObservationWriter,
        false,
        false,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::GitSessionWriter,
        false,
        false,
        false,
    ),
    process(
        SandboxSourceSecurityDomainV1::NixCachePublisher,
        false,
        false,
        false,
    ),
];

const fn process(
    domain: SandboxSourceSecurityDomainV1,
    network_ingress: bool,
    execute_nix: bool,
    execute_git: bool,
) -> SandboxSourceProcessConfinementV1 {
    SandboxSourceProcessConfinementV1 {
        domain,
        network_ingress,
        execute_nix,
        execute_git,
        linux_capabilities: 0,
        general_procfs: false,
        mount_authority: false,
        system_manager_authority: false,
    }
}

/// Names one protected secret or mutable object with an exclusive writer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SandboxSourceProtectedObjectV1 {
    /// Environment domain-journal authentication key.
    EnvironmentAuthorityMacKey = 1,
    /// Fixed environment authority journal.
    EnvironmentAuthorityJournal = 2,
    /// Nix build observation journal.
    NixObservationJournal = 3,
    /// Trust-domain Nix store database.
    NixStoreDatabase = 4,
    /// Trust-domain cache signing key.
    NixCacheSigningKey = 5,
    /// Git domain-journal authentication key.
    GitValidatorMacKey = 6,
    /// Fixed Git validator evidence journal.
    GitValidatorJournal = 7,
    /// Git authenticated-session journal.
    GitSessionJournal = 8,
    /// Git smart-effect observation journal.
    GitObservationJournal = 9,
    /// Receive-pack quarantine generation.
    GitReceiveQuarantine = 10,
    /// Broker-owned mutable exchange refs.
    GitExchangeReferences = 11,
    /// Immutable sanitized pack staging and final generations.
    GitPackPublication = 12,
    /// Git graph-validator signing key.
    GitValidatorSigningKey = 13,
    /// Immutable-pack publication attestation key.
    GitPackAttestationKey = 14,
    /// Nix build-observation journal authentication key.
    NixObservationMacKey = 15,
    /// Git authenticated-session journal authentication key.
    GitSessionMacKey = 16,
    /// Git smart-observation journal authentication key.
    GitObservationMacKey = 17,
    /// Immutable NAR staging and final publication namespace.
    NixCachePublication = 18,
}

impl SandboxSourceProtectedObjectV1 {
    /// Returns the stable SELinux object type required of compiled policy.
    #[must_use]
    pub const fn selinux_type(self) -> &'static str {
        match self {
            Self::EnvironmentAuthorityMacKey => "aos_sandbox_environment_authority_key_t",
            Self::EnvironmentAuthorityJournal => "aos_sandbox_environment_authority_state_t",
            Self::NixObservationJournal => "aos_sandbox_nix_observation_state_t",
            Self::NixStoreDatabase => "aos_sandbox_nix_store_database_t",
            Self::NixCacheSigningKey => "aos_sandbox_nix_cache_key_t",
            Self::GitValidatorMacKey => "aos_sandbox_git_validator_mac_key_t",
            Self::GitValidatorJournal => "aos_sandbox_git_validator_state_t",
            Self::GitSessionJournal => "aos_sandbox_git_session_state_t",
            Self::GitObservationJournal => "aos_sandbox_git_observation_state_t",
            Self::GitReceiveQuarantine => "aos_sandbox_git_quarantine_store_t",
            Self::GitExchangeReferences => "aos_sandbox_git_exchange_refs_t",
            Self::GitPackPublication => "aos_sandbox_git_pack_publication_t",
            Self::GitValidatorSigningKey => "aos_sandbox_git_validator_signing_key_t",
            Self::GitPackAttestationKey => "aos_sandbox_git_pack_attestation_key_t",
            Self::NixObservationMacKey => "aos_sandbox_nix_observation_key_t",
            Self::GitSessionMacKey => "aos_sandbox_git_session_key_t",
            Self::GitObservationMacKey => "aos_sandbox_git_observation_key_t",
            Self::NixCachePublication => "aos_sandbox_nix_cache_publication_t",
        }
    }
}

/// Selects one MAC-visible operation class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SandboxSourceMacPermissionV1 {
    /// Reads an exact protected object.
    Read = 1,
    /// Appends and synchronizes an authenticated journal.
    JournalWrite = 2,
    /// Creates private mutable quarantine objects.
    QuarantineWrite = 3,
    /// Renames a sealed object into an immutable final namespace.
    PublishSealed = 4,
    /// Updates refs under compare-and-swap after validation.
    PublishReferences = 5,
    /// Uses a key without exporting its bytes.
    UseKey = 6,
}

/// Declares one allowed domain/object/permission edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SandboxSourceMacRuleV1 {
    /// Process domain receiving the permission.
    pub domain: SandboxSourceSecurityDomainV1,
    /// Protected object constrained by the permission.
    pub object: SandboxSourceProtectedObjectV1,
    /// Exact permitted operation class.
    pub permission: SandboxSourceMacPermissionV1,
}

/// Complete closed allowlist for the dormant v1 source boundary.
pub const SANDBOX_SOURCE_MAC_RULES_V1: [SandboxSourceMacRuleV1; 25] = [
    rule(
        SandboxSourceSecurityDomainV1::Controller,
        SandboxSourceProtectedObjectV1::EnvironmentAuthorityJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::Controller,
        SandboxSourceProtectedObjectV1::GitValidatorJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::EnvironmentAuthorityWriter,
        SandboxSourceProtectedObjectV1::EnvironmentAuthorityMacKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::EnvironmentAuthorityWriter,
        SandboxSourceProtectedObjectV1::EnvironmentAuthorityJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixStoreOwner,
        SandboxSourceProtectedObjectV1::EnvironmentAuthorityJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixStoreOwner,
        SandboxSourceProtectedObjectV1::NixStoreDatabase,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixObservationWriter,
        SandboxSourceProtectedObjectV1::NixObservationJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixCachePublisher,
        SandboxSourceProtectedObjectV1::NixCacheSigningKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixCachePublisher,
        SandboxSourceProtectedObjectV1::NixCachePublication,
        SandboxSourceMacPermissionV1::PublishSealed,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitGraphValidator,
        SandboxSourceProtectedObjectV1::GitValidatorJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitGraphValidator,
        SandboxSourceProtectedObjectV1::GitValidatorMacKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitGraphValidator,
        SandboxSourceProtectedObjectV1::GitValidatorSigningKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitSmartGateway,
        SandboxSourceProtectedObjectV1::GitValidatorJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitSmartGateway,
        SandboxSourceProtectedObjectV1::GitSessionJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitQuarantineWriter,
        SandboxSourceProtectedObjectV1::GitReceiveQuarantine,
        SandboxSourceMacPermissionV1::QuarantineWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitQuarantineWriter,
        SandboxSourceProtectedObjectV1::GitValidatorJournal,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitPublisher,
        SandboxSourceProtectedObjectV1::GitReceiveQuarantine,
        SandboxSourceMacPermissionV1::Read,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitPublisher,
        SandboxSourceProtectedObjectV1::GitExchangeReferences,
        SandboxSourceMacPermissionV1::PublishReferences,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitPublisher,
        SandboxSourceProtectedObjectV1::GitPackPublication,
        SandboxSourceMacPermissionV1::PublishSealed,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitPublisher,
        SandboxSourceProtectedObjectV1::GitPackAttestationKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitObservationWriter,
        SandboxSourceProtectedObjectV1::GitObservationJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitSessionWriter,
        SandboxSourceProtectedObjectV1::GitSessionMacKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitSessionWriter,
        SandboxSourceProtectedObjectV1::GitSessionJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ),
    rule(
        SandboxSourceSecurityDomainV1::NixObservationWriter,
        SandboxSourceProtectedObjectV1::NixObservationMacKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
    rule(
        SandboxSourceSecurityDomainV1::GitObservationWriter,
        SandboxSourceProtectedObjectV1::GitObservationMacKey,
        SandboxSourceMacPermissionV1::UseKey,
    ),
];

const fn rule(
    domain: SandboxSourceSecurityDomainV1,
    object: SandboxSourceProtectedObjectV1,
    permission: SandboxSourceMacPermissionV1,
) -> SandboxSourceMacRuleV1 {
    SandboxSourceMacRuleV1 {
        domain,
        object,
        permission,
    }
}

/// Reports a structural defect in the dormant confinement declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxSourceConfinementErrorV1 {
    /// A duplicate allow edge would make the canonical representation ambiguous.
    DuplicateRule,
    /// Process declarations are duplicated or grant a forbidden ambient privilege.
    InvalidProcessConfinement,
    /// A protected mutable object has no exclusive writer.
    MissingExclusiveWriter,
    /// One process can both receive untrusted Git bytes and publish them.
    GitIngressPublisherCollapse,
    /// One process can both execute builds and write their protected observations.
    NixEffectObserverCollapse,
    /// A protected MAC or signing key does not have exactly one user domain.
    NonExclusiveKeyUse,
}

/// Validates the closed key, writer, and separation-of-duty invariants.
///
/// # Errors
///
/// Returns [`SandboxSourceConfinementErrorV1`] when the declaration contains
/// duplicates, lacks an exact writer, or collapses a required trust boundary.
pub fn validate_sandbox_source_confinement_v1() -> Result<(), SandboxSourceConfinementErrorV1> {
    let mut sorted = SANDBOX_SOURCE_MAC_RULES_V1;
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SandboxSourceConfinementErrorV1::DuplicateRule);
    }

    let mut process_domains =
        SANDBOX_SOURCE_PROCESS_CONFINEMENT_V1.map(|declaration| declaration.domain);
    process_domains.sort_unstable();
    if process_domains.windows(2).any(|pair| pair[0] == pair[1])
        || SANDBOX_SOURCE_PROCESS_CONFINEMENT_V1
            .iter()
            .any(|declaration| {
                declaration.linux_capabilities != 0
                    || declaration.general_procfs
                    || declaration.mount_authority
                    || declaration.system_manager_authority
                    || (declaration.network_ingress
                        && declaration.domain != SandboxSourceSecurityDomainV1::GitSmartGateway)
            })
    {
        return Err(SandboxSourceConfinementErrorV1::InvalidProcessConfinement);
    }

    let exclusive_writers = [
        (
            SandboxSourceProtectedObjectV1::EnvironmentAuthorityJournal,
            SandboxSourceSecurityDomainV1::EnvironmentAuthorityWriter,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::NixObservationJournal,
            SandboxSourceSecurityDomainV1::NixObservationWriter,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::NixStoreDatabase,
            SandboxSourceSecurityDomainV1::NixStoreOwner,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::NixCachePublication,
            SandboxSourceSecurityDomainV1::NixCachePublisher,
            SandboxSourceMacPermissionV1::PublishSealed,
        ),
        (
            SandboxSourceProtectedObjectV1::GitValidatorJournal,
            SandboxSourceSecurityDomainV1::GitGraphValidator,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::GitSessionJournal,
            SandboxSourceSecurityDomainV1::GitSessionWriter,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::GitObservationJournal,
            SandboxSourceSecurityDomainV1::GitObservationWriter,
            SandboxSourceMacPermissionV1::JournalWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::GitReceiveQuarantine,
            SandboxSourceSecurityDomainV1::GitQuarantineWriter,
            SandboxSourceMacPermissionV1::QuarantineWrite,
        ),
        (
            SandboxSourceProtectedObjectV1::GitExchangeReferences,
            SandboxSourceSecurityDomainV1::GitPublisher,
            SandboxSourceMacPermissionV1::PublishReferences,
        ),
        (
            SandboxSourceProtectedObjectV1::GitPackPublication,
            SandboxSourceSecurityDomainV1::GitPublisher,
            SandboxSourceMacPermissionV1::PublishSealed,
        ),
    ];
    for (object, writer, permission) in exclusive_writers {
        let writers = SANDBOX_SOURCE_MAC_RULES_V1
            .iter()
            .filter(|candidate| candidate.object == object && candidate.permission == permission)
            .map(|candidate| candidate.domain)
            .collect::<Vec<_>>();
        if writers.as_slice() != [writer] {
            return Err(SandboxSourceConfinementErrorV1::MissingExclusiveWriter);
        }
    }
    if has_permission(
        SandboxSourceSecurityDomainV1::GitQuarantineWriter,
        SandboxSourceProtectedObjectV1::GitExchangeReferences,
        SandboxSourceMacPermissionV1::PublishReferences,
    ) {
        return Err(SandboxSourceConfinementErrorV1::GitIngressPublisherCollapse);
    }
    if has_permission(
        SandboxSourceSecurityDomainV1::NixStoreOwner,
        SandboxSourceProtectedObjectV1::NixObservationJournal,
        SandboxSourceMacPermissionV1::JournalWrite,
    ) {
        return Err(SandboxSourceConfinementErrorV1::NixEffectObserverCollapse);
    }
    for key in [
        SandboxSourceProtectedObjectV1::EnvironmentAuthorityMacKey,
        SandboxSourceProtectedObjectV1::NixCacheSigningKey,
        SandboxSourceProtectedObjectV1::GitValidatorMacKey,
        SandboxSourceProtectedObjectV1::GitValidatorSigningKey,
        SandboxSourceProtectedObjectV1::GitPackAttestationKey,
        SandboxSourceProtectedObjectV1::NixObservationMacKey,
        SandboxSourceProtectedObjectV1::GitSessionMacKey,
        SandboxSourceProtectedObjectV1::GitObservationMacKey,
    ] {
        if SANDBOX_SOURCE_MAC_RULES_V1
            .iter()
            .filter(|rule| {
                rule.object == key && rule.permission == SandboxSourceMacPermissionV1::UseKey
            })
            .count()
            != 1
        {
            return Err(SandboxSourceConfinementErrorV1::NonExclusiveKeyUse);
        }
    }
    Ok(())
}

/// Commits the exact closed confinement table for offline policy comparison.
#[must_use]
pub fn sandbox_source_confinement_digest_v1() -> ObjectDigest {
    let mut digest = Sha256::new()
        .chain_update(b"aos.sandbox.source-confinement-policy.v1\0")
        .chain_update((SANDBOX_SOURCE_MAC_RULES_V1.len() as u32).to_be_bytes());
    for rule in SANDBOX_SOURCE_MAC_RULES_V1 {
        let domain_type = rule.domain.selinux_type();
        let object_type = rule.object.selinux_type();
        digest = digest
            .chain_update([rule.domain as u8, rule.object as u8, rule.permission as u8])
            .chain_update((domain_type.len() as u16).to_be_bytes())
            .chain_update(domain_type.as_bytes())
            .chain_update((object_type.len() as u16).to_be_bytes())
            .chain_update(object_type.as_bytes());
    }
    for declaration in SANDBOX_SOURCE_PROCESS_CONFINEMENT_V1 {
        digest = digest
            .chain_update([declaration.domain as u8])
            .chain_update([u8::from(declaration.network_ingress)])
            .chain_update([u8::from(declaration.execute_nix)])
            .chain_update([u8::from(declaration.execute_git)])
            .chain_update(declaration.linux_capabilities.to_be_bytes())
            .chain_update([u8::from(declaration.general_procfs)])
            .chain_update([u8::from(declaration.mount_authority)])
            .chain_update([u8::from(declaration.system_manager_authority)]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn has_permission(
    domain: SandboxSourceSecurityDomainV1,
    object: SandboxSourceProtectedObjectV1,
    permission: SandboxSourceMacPermissionV1,
) -> bool {
    SANDBOX_SOURCE_MAC_RULES_V1.contains(&SandboxSourceMacRuleV1 {
        domain,
        object,
        permission,
    })
}
