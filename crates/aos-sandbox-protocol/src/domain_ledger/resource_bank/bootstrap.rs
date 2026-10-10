//! Owns complete passive enrollment subdivision and record comparison.
//!
//! Image validation and all subdivisions precede Native transaction-ID generation.
//! Initial claim hashes remain a separate reached operation after that generation.
//!
//! ```text
//! enrollment = three-heads || optional-host-head || two-initial-claims
//!              || optional-host-claims || P || I || Q || R
//! member-count = 5 | 8 | 9 | 10 | 11 | 12 (selected by the closed image suffix)
//! ```

use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceVector};
use sha2::{Digest as _, Sha256};

use super::{
    AccountHead, AccountKind, Claim, ClaimCut, ClaimPurpose, ClaimState, EnrollmentIdentity,
    EnrollmentMutation, ImageBootstrapPolicy, JournalRecord, JournalTransaction,
    NativeLayoutDemand, RecordNamespace, ResourceBankDataError, codec, matches_record, replay,
};

/// Computes all enrollment subdivisions before Native transaction-ID generation.
///
/// # Errors
/// Retains original image validation, identity hashing and arithmetic refusal order.
pub fn prepare_enrollment_subdivisions(
    identity: EnrollmentIdentity,
    policy: ImageBootstrapPolicy,
    layout: NativeLayoutDemand,
) -> Result<
    (
        [AccountHead; 3],
        Option<(AccountHead, [Claim; 2])>,
        Option<Claim>,
        Option<Claim>,
        Option<Claim>,
        Option<Claim>,
    ),
    ResourceBankDataError,
> {
    policy.validate(layout)?;
    let node = policy.node;
    let controller = account_id(identity, b"controller");
    let components = account_id(identity, b"components");
    let root_account = ResourceAccount::from_usage(
        ResourceCeilings::bounded(policy.capacity),
        policy.baseline,
        ResourceVector::ZERO,
    )?
    .reserve(policy.controller)?
    .reserve(policy.components)?;
    let head = |id, parent, kind, account, baseline| AccountHead {
        enrollment: identity,
        id,
        parent,
        kind,
        generation: 1,
        project: [0; 16],
        sandbox: [0; 16],
        tree_revision: [0; 32],
        account,
        baseline,
    };

    // Fixed aggregate demand stays committed inside the once-paid grant;
    // only the explicit Host and Root subdivisions remain reserved.
    let components_baseline = match policy.host {
        Some(host) => policy
            .components
            .checked_sub(host.service)?
            .checked_sub(host.control)?,
        None => policy.components,
    }
    .checked_sub(policy.root_receiving.unwrap_or(ResourceVector::ZERO))?;
    let child_account = |amount, baseline| {
        ResourceAccount::from_usage(
            ResourceCeilings::bounded(amount),
            baseline,
            ResourceVector::ZERO,
        )
    };

    let mut heads = [
        head(
            node,
            [0; 16],
            AccountKind::Node,
            root_account,
            policy.baseline,
        ),
        head(
            controller,
            node,
            AccountKind::Controller,
            child_account(policy.controller, policy.controller)?,
            policy.controller,
        ),
        head(
            components,
            node,
            AccountKind::Components,
            child_account(policy.components, components_baseline)?,
            components_baseline,
        ),
    ];
    let claim = |child: [u8; 16], amount, purpose| Claim {
        enrollment: identity,
        id: account_id(identity, &child),
        account: node,
        child,
        owner: identity.manifest,
        purpose,
        operation: [0; 16],
        project: [0; 16],
        sandbox: [0; 16],
        tree_revision: [0; 32],
        cut: ClaimCut::BootLifetime,
        genesis_instance: [0; 32],
        amount,
        state: ClaimState::Reserved,
    };
    let first_global = if let Some(prefix) = policy.first_global_prefix {
        let retained_service = policy
            .controller
            .checked_sub(prefix)?
            .checked_sub(
                policy
                    .nix_original_start_intake
                    .unwrap_or(ResourceVector::ZERO),
            )?
            .checked_sub(policy.q04_original_intake.unwrap_or(ResourceVector::ZERO))?;
        heads[1].baseline = retained_service;
        heads[1].account = ResourceAccount::from_usage(
            ResourceCeilings::bounded(policy.controller),
            retained_service,
            ResourceVector::ZERO,
        )?
        .reserve(prefix)?
        .reserve(
            policy
                .nix_original_start_intake
                .unwrap_or(ResourceVector::ZERO),
        )?
        .reserve(policy.q04_original_intake.unwrap_or(ResourceVector::ZERO))?;
        Some(Claim {
            id: account_id(identity, b"controller-first-global-prefix-v1"),
            account: controller,
            ..claim([0; 16], prefix, ClaimPurpose::ControllerFirstGlobalPrefix)
        })
    } else {
        None
    };
    let nix_intake = policy.nix_original_start_intake.map(|amount| Claim {
        id: account_id(identity, b"controller-nix-original-start-intake-v1"),
        account: controller,
        ..claim([0; 16], amount, ClaimPurpose::NixOriginalStartIntake)
    });
    let q04_intake = policy.q04_original_intake.map(|amount| Claim {
        id: account_id(identity, b"controller-q04-original-intake-v1"),
        account: controller,
        ..claim([0; 16], amount, ClaimPurpose::Q04OriginalIntake)
    });
    let host = if let Some(host_policy) = policy.host {
        let host_id = account_id(identity, b"host-component-v2");
        let amount = host_policy.service.checked_add(host_policy.control)?;
        heads[2].account = heads[2].account.reserve(amount)?;
        let host_account = ResourceAccount::from_usage(
            ResourceCeilings::bounded(amount),
            host_policy.service,
            ResourceVector::ZERO,
        )?
        .reserve(host_policy.control)?;
        let host_head = head(
            host_id,
            components,
            AccountKind::Operation,
            host_account,
            host_policy.service,
        );
        let host_claim = Claim {
            account: components,
            ..claim(host_id, amount, ClaimPurpose::HostComponentBootstrap)
        };
        let control_claim = Claim {
            id: account_id(identity, b"host-control-v2"),
            account: host_id,
            ..claim(
                [0; 16],
                host_policy.control,
                ClaimPurpose::HostControlInterval,
            )
        };
        Some((host_head, [host_claim, control_claim]))
    } else {
        None
    };
    let root_receiving = if let Some(amount) = policy.root_receiving {
        heads[2].account = heads[2].account.reserve(amount)?;
        Some(Claim {
            id: account_id(identity, b"root-receiving-v1"),
            account: components,
            ..claim([0; 16], amount, ClaimPurpose::RootReceiving)
        })
    } else {
        None
    };
    Ok((
        heads,
        host,
        first_global,
        nix_intake,
        q04_intake,
        root_receiving,
    ))
}

/// Builds the two original claim hashes after the Native transaction-ID stage.
pub fn initial_enrollment_claims(
    identity: EnrollmentIdentity,
    policy: ImageBootstrapPolicy,
    heads: &[AccountHead; 3],
) -> [Claim; 2] {
    let node = policy.node;
    let claim = |child: [u8; 16], amount, purpose| Claim {
        enrollment: identity,
        id: account_id(identity, &child),
        account: node,
        child,
        owner: identity.manifest,
        purpose,
        operation: [0; 16],
        project: [0; 16],
        sandbox: [0; 16],
        tree_revision: [0; 32],
        cut: ClaimCut::BootLifetime,
        genesis_instance: [0; 32],
        amount,
        state: ClaimState::Reserved,
    };
    [
        claim(
            heads[1].id,
            policy.controller,
            ClaimPurpose::ControllerBootstrap,
        ),
        claim(
            heads[2].id,
            policy.components,
            ClaimPurpose::ComponentEnvelope,
        ),
    ]
}

impl EnrollmentMutation<'_> {
    /// Runs the complete original ordered enrollment transaction recipe.
    ///
    /// # Errors
    /// Retains canonical record, transaction and exact predecessor failures.
    pub fn transaction(&self) -> Result<JournalTransaction, ResourceBankDataError> {
        let members = if self.root_receiving.is_some() {
            12
        } else if (*self.q04_intake).is_some() {
            11
        } else if self.nix_intake.is_some() {
            10
        } else if self.first_global.is_some() {
            9
        } else if self.host.is_some() {
            8
        } else {
            5
        };
        let mut records = Vec::with_capacity(members);
        for head in *self.heads {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, head.id).to_vec(),
                codec::encode_head(head)?.to_vec(),
            ));
        }
        if let Some((head, _)) = *self.host {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, head.id).to_vec(),
                codec::encode_head(head)?.to_vec(),
            ));
        }
        for claim in *self.claims {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some((_, claims)) = *self.host {
            for claim in claims {
                records.push(JournalRecord::put(
                    RecordNamespace::ControllerResourceReservation,
                    replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                    codec::encode_claim(claim)?.to_vec(),
                ));
            }
        }
        if let Some(claim) = *self.first_global {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = *self.nix_intake {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = *self.q04_intake {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = *self.root_receiving {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        Ok(JournalTransaction::new(*self.transaction_id, records)
            .map_err(ResourceBankDataError::Transaction)?)
    }

    /// Runs the complete original ordered enrollment require_exact recipe.
    ///
    /// # Errors
    /// Retains canonical record, transaction and exact predecessor failures.
    pub fn require_exact(
        &self,
        state: &replay::State,
        transaction: &JournalTransaction,
    ) -> Result<(), ResourceBankDataError> {
        if replay::validate(state)?.is_some()
            || transaction.id() != self.transaction_id
            || transaction.records().len()
                != if self.root_receiving.is_some() {
                    12
                } else if (*self.q04_intake).is_some() {
                    11
                } else if self.nix_intake.is_some() {
                    10
                } else if self.first_global.is_some() {
                    9
                } else if self.host.is_some() {
                    8
                } else {
                    5
                }
        {
            return Err(ResourceBankDataError::Conflict);
        }
        for (record, head) in transaction.records()[..3].iter().zip(*self.heads) {
            if !matches_record(
                record,
                replay::HEAD_PREFIX,
                head.id,
                &codec::encode_head(head)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        let claim_offset = if self.host.is_some() { 4 } else { 3 };
        if let Some((head, claims)) = *self.host {
            if !matches_record(
                &transaction.records()[3],
                replay::HEAD_PREFIX,
                head.id,
                &codec::encode_head(head)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
            for (record, claim) in transaction.records()[6..].iter().zip(claims) {
                if !matches_record(
                    record,
                    replay::CLAIM_PREFIX,
                    claim.id,
                    &codec::encode_claim(claim)?,
                ) {
                    return Err(ResourceBankDataError::Conflict);
                }
            }
        }
        for (record, claim) in transaction.records()[claim_offset..claim_offset + 2]
            .iter()
            .zip(*self.claims)
        {
            if !matches_record(
                record,
                replay::CLAIM_PREFIX,
                claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(claim) = *self.first_global {
            if !matches_record(
                &transaction.records()[8],
                replay::CLAIM_PREFIX,
                claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(claim) = *self.nix_intake {
            if !matches_record(
                &transaction.records()[9],
                replay::CLAIM_PREFIX,
                claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(claim) = *self.q04_intake {
            if !matches_record(
                &transaction.records()[10],
                replay::CLAIM_PREFIX,
                claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(claim) = *self.root_receiving {
            if !matches_record(
                &transaction.records()[11],
                replay::CLAIM_PREFIX,
                claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        Ok(())
    }

    /// Checks every retained row after the caller's actual transaction-presence check.
    ///
    /// # Errors
    /// Rejects missing or changed original heads and claims in their original order.
    pub fn require_returned_rows(
        &self,
        state: &replay::State,
    ) -> Result<(), ResourceBankDataError> {
        for expected in *self.heads {
            if replay::find_head(state, expected.id)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        for expected in *self.claims {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceBankDataError::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some((head, claims)) = *self.host {
            if replay::find_head(state, head.id)? != head {
                return Err(ResourceBankDataError::Conflict);
            }
            for expected in claims {
                let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                    .ok_or(ResourceBankDataError::Conflict)?;
                if codec::decode_claim(actual)? != expected {
                    return Err(ResourceBankDataError::Conflict);
                }
            }
        }
        if let Some(expected) = *self.first_global {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceBankDataError::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(expected) = *self.nix_intake {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceBankDataError::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(expected) = *self.q04_intake {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceBankDataError::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        if let Some(expected) = *self.root_receiving {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceBankDataError::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        Ok(())
    }
}

pub(super) fn account_id(identity: EnrollmentIdentity, role: &[u8]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"AOS-resource-account-v1\0");
    hash.update(identity.node);
    hash.update(identity.epoch);
    hash.update(role);
    let hash = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}
