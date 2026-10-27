//! Injects malformed certificates only into genuine native test publications.
//!
//! Current paired authorization remains genuine for both pre-sign ancestry and
//! post-sign binding mutations. Witness completion follows actual source signing;
//! the destination then signs the complete candidate before boundary verification.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use super::invalid;
use crate::store::StoreFailure;
use terrane_format::refs::{Commit, EntryOrigin};

/// Changes one authenticated certificate-bearing candidate in a native test.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CertificateMutation {
    /// Changes the complete destination message after source signing.
    Message,
    /// Changes the complete destination timestamp after source signing.
    Timestamp,
    /// Moves a certified destination receipt to an uncovered path.
    ReceiptPath,
    /// Changes the attested source commit identity.
    SourceCommit,
    /// Changes the attested source root identity.
    SourceRoot,
    /// Moves the attested source selector to an uncovered local path.
    SourcePath,
    /// Substitutes an unrelated private source domain.
    SourceDomain,
    /// Corrupts the genuine dedicated source-role signature.
    Signature,
    /// Changes an independently copied attribute's producer claim.
    AttributeOrigin,
    /// Adds an actual unrelated native commit before genuine source signing.
    UnanchoredParent([u8; 32]),
}

struct Injection {
    mutation: CertificateMutation,
    observed: Arc<AtomicBool>,
    prepared: AtomicBool,
}

/// Proves that a mutation reached the genuinely source-signed candidate.
pub(crate) struct CertificateMutationWitness(Arc<AtomicBool>);

impl CertificateMutationWitness {
    /// Reports whether the exact armed mutation was applied successfully.
    pub(crate) fn applied(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

static PENDING: OnceLock<Mutex<BTreeMap<PathBuf, Injection>>> = OnceLock::new();

/// Arms one mutation for the exact independently opened destination namespace.
///
/// # Errors
/// Rejects synchronization failure or another mutation already armed for this root.
pub(crate) fn corrupt_next_certificate(
    root: &Path,
    mutation: CertificateMutation,
) -> Result<CertificateMutationWitness, StoreFailure> {
    let mut pending = PENDING
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| invalid())?;
    if pending.contains_key(root) {
        return Err(invalid());
    }
    let observed = Arc::new(AtomicBool::new(false));
    pending.insert(
        root.to_owned(),
        Injection {
            mutation,
            observed: Arc::clone(&observed),
            prepared: AtomicBool::new(false),
        },
    );
    Ok(CertificateMutationWitness(observed))
}

/// Adds the actual unrelated parent before the dedicated signer sees the message.
///
/// # Errors
/// Rejects unavailable synchronization or a parent already present in the message.
pub(super) fn apply_before_sign(root: &Path, commit: &mut Commit) -> Result<(), StoreFailure> {
    let pending = PENDING
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| invalid())?;
    if let Some(injection) = pending.get(root)
        && let CertificateMutation::UnanchoredParent(parent) = injection.mutation
    {
        if commit.parents.contains(&parent) {
            return Err(invalid());
        }
        commit.parents.push(parent);
        injection.prepared.store(true, Ordering::Release);
    }
    Ok(())
}

/// Applies and consumes the mutation armed for this actual destination.
///
/// # Errors
/// Rejects synchronization failure, timestamp overflow, or a candidate lacking
/// the certificate, source selector, or attribute required by the armed mutation,
/// or an ancestry mutation that did not run before actual source signing.
pub(super) fn apply(root: &Path, commit: &mut Commit) -> Result<(), StoreFailure> {
    let Some(injection) = PENDING
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| invalid())?
        .remove(root)
    else {
        return Ok(());
    };
    match injection.mutation {
        CertificateMutation::UnanchoredParent(parent) => {
            if !injection.prepared.load(Ordering::Acquire) || !commit.parents.contains(&parent) {
                return Err(invalid());
            }
        }
        CertificateMutation::Message => commit.message.push_str(" altered after source signing"),
        CertificateMutation::Timestamp => {
            commit.timestamp = commit.timestamp.checked_add(1).ok_or_else(invalid)?;
        }
        mutation => {
            let receipt = commit
                .profile_pair
                .entry_receipts
                .as_mut()
                .and_then(|receipts| {
                    receipts
                        .iter_mut()
                        .find(|receipt| receipt.disclosure_proof.is_some())
                })
                .ok_or_else(invalid)?;
            match mutation {
                CertificateMutation::ReceiptPath => receipt.path = b"uncovered".to_vec(),
                CertificateMutation::SourceCommit => {
                    receipt
                        .reintroduced_from
                        .as_mut()
                        .ok_or_else(invalid)?
                        .commit[0] ^= 1;
                }
                CertificateMutation::SourceRoot => {
                    receipt.reintroduced_from.as_mut().ok_or_else(invalid)?.root[0] ^= 1;
                }
                CertificateMutation::SourcePath => {
                    receipt.reintroduced_from.as_mut().ok_or_else(invalid)?.path =
                        b"uncovered".to_vec();
                }
                CertificateMutation::SourceDomain => {
                    receipt
                        .disclosure_proof
                        .as_mut()
                        .ok_or_else(invalid)?
                        .source_domain = "private:unrelated".into();
                }
                CertificateMutation::Signature => {
                    receipt
                        .disclosure_proof
                        .as_mut()
                        .ok_or_else(invalid)?
                        .signature[0] ^= 1;
                }
                CertificateMutation::AttributeOrigin => {
                    let (_, origin) = receipt
                        .attributes
                        .as_mut()
                        .and_then(|attributes| {
                            attributes.iter_mut().find(|(name, _)| name == "note")
                        })
                        .ok_or_else(invalid)?;
                    *origin = EntryOrigin::Current;
                }
                CertificateMutation::Message
                | CertificateMutation::Timestamp
                | CertificateMutation::UnanchoredParent(_) => {
                    return Err(invalid());
                }
            }
        }
    }
    injection.observed.store(true, Ordering::Release);
    Ok(())
}
