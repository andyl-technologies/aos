//! Creates the original worker objects under genuine pending Mount custody.
//!
//! The producer derives every plan coordinate from the authenticated original
//! request, location-MACed reservation/effect and physically retained Host
//! namespace. It retains that actual Mount writer alongside its own fresh
//! FUSE OFD, detached mount, sealed plan, private channel and cancellation
//! ends. No decoded plan, received descriptor or historical row can construct
//! this borrow, and it is not a connected worker or Root content-read guard.
//!
//! The location-MACed one-shot obligation has the closed payload:
//!
//! ```text
//! AOSFWC01 | original-reservation[32] | worker[16] | boot[16] | plan-digest[32]
//! ```
//!
//! It records ambiguous creation custody only. Opening this historical marker
//! never reconstructs a fresh connection, namespace, worker or live guard.

use aos_sandbox_core::encode_object_descriptor;
use aos_sandbox_linux::fuse_worker_objects::MountCreatedFuseWorkerObjectsV1;
use aos_sandbox_protocol::fuse_worker_preparation::WorkerPreparationPlanV1;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use super::*;

const START_PREFIX: &[u8] = b"aos.mount.fuse.worker-object-start.v1\0";
const START_MAGIC: &[u8; 8] = b"AOSFWC01";

/// Retains the original Mount writer and its internally created worker objects.
///
/// This preparation owner supplies no attachment/readiness, metadata or backing
/// permission. The actual Host launch, all descriptor-copy barriers, original
/// worker HELLO, bounded kernel INIT, retained namespace idmap and independent
/// live Root/Mount resource-read join remain mandatory downstream.
#[must_use = "retain original writer/kernel custody through preparation or reconciliation"]
pub struct PreparedMountFuseWorkerObjectsV1<'cut, 'mount, W: MountWorker> {
    owner: &'cut mut HeldMountFuseIntentPreparationV1<'mount, W>,
    objects: MountCreatedFuseWorkerObjectsV1,
    plan: WorkerPreparationPlanV1,
}

/// Co-owns one original four-role launch table and the genuine pending Mount.
///
/// The table contains no executable or cancellation writer. Its creation does
/// not establish Host acceptance, endpoint-copy absence, HELLO or INIT. The
/// actual signed Host session must consume the table under these same retained
/// owners. No row, decoded plan or received descriptor can construct this type.
#[must_use = "retain original handoff and durable escrow through reconciliation"]
pub struct PreparedMountFuseWorkerHandoffV1<'cut, 'mount, W: MountWorker> {
    // Close local role owners before the objects/cancellation writer on Drop.
    roles: Option<[OwnedFd; 4]>,
    preparation: PreparedMountFuseWorkerObjectsV1<'cut, 'mount, W>,
}

impl<'mount, W: MountWorker> HeldMountFuseIntentPreparationV1<'mount, W> {
    /// Creates the worker's original objects from this actual pending owner.
    ///
    /// There are no caller-supplied plan coordinates, namespace, challenge or
    /// incoming FUSE connection. The fresh fixed-device OFD is created here
    /// only after the exact reservation is durable. It remains co-owned with
    /// its detached mount; the original namespace is retained but cannot be
    /// idmapped before real kernel INIT accepts the required flags.
    ///
    /// # Errors
    ///
    /// Rejects stale original owner/scope/reservation/effect, unsupported fixed
    /// MAC labels or kernel objects, invalid plan boundaries or creation
    /// failure. A failure poisons this borrow and preserves every durable row;
    /// it never frees a generation, slot or lease for automatic reuse.
    pub fn prepare_original_worker_objects(
        &mut self,
    ) -> Result<PreparedMountFuseWorkerObjectsV1<'_, 'mount, W>> {
        let result = (|| {
            self.recheck()?;
            let plan = self.original_worker_plan()?;
            let bytes = plan
                .encode()
                .map_err(|_| MountError::Fence("original FUSE worker plan is invalid"))?;
            // Commit the exact plan's one-shot obligation before any fresh
            // kernel object. Crash/error never permits another connection for
            // this reservation, even if no Host launch could be confirmed.
            self.commit_worker_object_start(&plan)?;
            let objects = MountCreatedFuseWorkerObjectsV1::create(
                plan.worker_instance,
                &bytes,
                self.scope.user_namespace(),
            )
            .map_err(|error| {
                MountError::Worker(format!("original worker objects failed: {error}"))
            })?;
            self.recheck()?;
            Ok((objects, plan))
        })();
        let (objects, plan) = match result {
            Ok(prepared) => prepared,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        Ok(PreparedMountFuseWorkerObjectsV1 {
            owner: self,
            objects,
            plan,
        })
    }

    fn original_worker_plan(&self) -> Result<WorkerPreparationPlanV1> {
        let effect_bytes = self
            .broker
            .journal
            .get(RecordNamespace::Effect, &self.request.request_id())
            .ok_or(MountError::Fence("original FUSE effect disappeared"))?;
        let effect = self
            .broker
            .authority
            .open_effect(&self.request.request_id(), effect_bytes)
            .map_err(|_| MountError::Fence("original FUSE effect authentication failed"))?;
        if effect.status() != BrokerEffectStatusV1::Pending {
            return Err(MountError::Fence(
                "original worker needs pending Mount custody",
            ));
        }
        let reservation = &self.origin.reservation;
        // Both halves come from the existing fixed kernel random-UUID reader,
        // not from a caller, received channel, timestamp or reservation ID.
        let mut challenge = [0; 32];
        challenge[..16].copy_from_slice(&broker_instance_id()?);
        challenge[16..].copy_from_slice(&broker_instance_id()?);
        let mut slot = b"aos-fuse-worker-original-slot-v1\0".to_vec();
        slot.extend_from_slice(self.decoded.namespace_allocation_digest());
        slot.extend_from_slice(&self.origin.destination_record_digest);
        for coordinate in [
            self.origin.destination_device,
            self.origin.destination_inode,
            reservation.user_namespace_device,
            reservation.user_namespace_inode,
            reservation.user_namespace_generation,
        ] {
            slot.extend_from_slice(&coordinate.to_le_bytes());
        }

        Ok(WorkerPreparationPlanV1 {
            worker_instance: reservation.worker_instance_id,
            kernel_boot: reservation.kernel_boot_id,
            challenge,
            controller_request: self.request.signed_request_digest(),
            mount_reservation: self.reservation_digest()?,
            assignment: reservation.assignment.assignment_digest,
            attachment: *self.decoded.desired_record_digest(),
            original_view_descriptor: digest(&encode_object_descriptor(
                self.decoded.intent().view(),
            )),
            resolved_policy_descriptor: digest(&encode_object_descriptor(
                self.decoded.accepted_policy(),
            )),
            mount_slot: digest(&slot),
            ownership_lease: *effect.local_lease_record().renewal_nonce(),
            ownership_lease_expires_boottime_ns: reservation.lease_expires_boottime_ns,
            preparation_deadline_boottime_ns: self.request.deadline_boottime_nanoseconds(),
        })
    }

    fn worker_object_start(&self, plan: &WorkerPreparationPlanV1) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut key = START_PREFIX.to_vec();
        key.extend_from_slice(&self.request.request_id());
        let payload = encode_worker_object_start(self.reservation_digest()?, plan)?;
        Ok((key, payload))
    }

    fn commit_worker_object_start(&mut self, plan: &WorkerPreparationPlanV1) -> Result<()> {
        self.recheck()?;
        let (key, payload) = self.worker_object_start(plan)?;
        if self
            .broker
            .journal
            .get(RecordNamespace::AuthorityPublication, &key)
            .is_some()
        {
            return Err(MountError::Fence(
                "original worker objects require reconciliation",
            ));
        }
        let authenticated = self
            .broker
            .authority
            .seal_fuse_origin(&key, &payload)
            .map_err(|_| MountError::Fence("worker object-start authentication failed"))?;
        let transaction = JournalTransaction::new(
            worker_object_start_transaction_id(self.request.request_id(), &payload),
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                key,
                authenticated,
            )],
        )?;
        self.broker.journal.commit(&transaction)?;
        self.sequence = self.broker.journal.snapshot_sequence();
        self.require_worker_object_start(plan)?;
        self.recheck()
    }

    fn require_worker_object_start(&self, plan: &WorkerPreparationPlanV1) -> Result<()> {
        let (key, payload) = self.worker_object_start(plan)?;
        let record = self
            .broker
            .journal
            .get(RecordNamespace::AuthorityPublication, &key)
            .ok_or(MountError::Fence(
                "original worker object-start disappeared",
            ))?;
        let opened = self
            .broker
            .authority
            .open_fuse_origin(&key, record)
            .map_err(|_| MountError::Fence("worker object-start authentication failed"))?;
        if opened != payload {
            return Err(MountError::Fence("original worker object-start changed"));
        }
        Ok(())
    }
}

// Commits the original request and exact reservation/plan payload in a distinct
// transaction domain. The journal rejects a forbidden all-zero truncation.
fn worker_object_start_transaction_id(request: [u8; 16], payload: &[u8]) -> [u8; 16] {
    let commitment = Sha256::new()
        .chain_update(b"aos.mount.fuse.worker-object-start.transaction.v1\0")
        .chain_update(request)
        .chain_update(payload)
        .finalize();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&commitment[..16]);
    transaction_id
}

// Pure framing, not a decoder or authority factory. The producer's real held
// writer authenticates the exact payload at its original request-ID location.
fn encode_worker_object_start(
    reservation: [u8; 32],
    plan: &WorkerPreparationPlanV1,
) -> Result<Vec<u8>> {
    if reservation == [0; 32] {
        return Err(MountError::Fence("original reservation digest is invalid"));
    }
    let mut payload = START_MAGIC.to_vec();
    payload.extend_from_slice(&reservation);
    payload.extend_from_slice(&plan.worker_instance);
    payload.extend_from_slice(&plan.kernel_boot);
    payload.extend_from_slice(
        &plan
            .digest()
            .map_err(|_| MountError::Fence("original worker plan digest failed"))?,
    );
    Ok(payload)
}

impl<W: MountWorker> PreparedMountFuseWorkerObjectsV1<'_, '_, W> {
    /// Borrows exact plan coordinates for comparison, never a read grant.
    #[must_use]
    pub const fn plan(&self) -> &WorkerPreparationPlanV1 {
        &self.plan
    }

    /// Rechecks the genuine original owner and retained namespace join.
    ///
    /// # Errors
    ///
    /// Rejects changed names/head/reservation/physical slot/Host custody or a
    /// namespace substitution. A failure preserves the durable obligation and
    /// refuses continued preparation; no connected worker is inferred here.
    pub fn recheck(&mut self) -> Result<()> {
        self.owner.recheck()?;
        if let Err(error) = self.owner.require_worker_object_start(&self.plan) {
            self.owner.failed = true;
            return Err(error);
        }
        if self.objects.user_namespace().identity() != self.owner.scope.user_namespace().identity()
        {
            self.owner.failed = true;
            return Err(MountError::Fence("original worker namespace changed"));
        }
        self.owner.recheck()
    }
}

impl<'cut, 'mount, W: MountWorker> PreparedMountFuseWorkerObjectsV1<'cut, 'mount, W> {
    /// Moves the sole original worker endpoint into a one-shot Host table.
    ///
    /// The plan/FUSE/cancellation-reader copies originate only from this
    /// internally created bundle. Its original Mount writer, fresh FUSE OFD,
    /// detached mount, namespace and cancellation writer remain co-owned.
    /// Errors poison the held owner; the already durable start marker and all
    /// reservation/effect rows remain occupied for explicit reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects changed held custody, a previously consumed endpoint, changed
    /// labels or failed duplication. No failure permits a fresh connection or
    /// role table to be minted from the historical marker.
    pub fn into_original_host_handoff(
        mut self,
    ) -> Result<PreparedMountFuseWorkerHandoffV1<'cut, 'mount, W>> {
        let result = (|| {
            self.recheck()?;
            let roles = self
                .objects
                .take_original_worker_launch_roles()
                .map_err(|error| {
                    MountError::Worker(format!("original worker handoff failed: {error}"))
                })?;
            self.recheck()?;
            Ok(roles)
        })();
        match result {
            Ok(roles) => Ok(PreparedMountFuseWorkerHandoffV1 {
                roles: Some(roles),
                preparation: self,
            }),
            Err(error) => {
                self.owner.failed = true;
                Err(error)
            }
        }
    }
}

impl<W: MountWorker> PreparedMountFuseWorkerHandoffV1<'_, '_, W> {
    /// Borrows exact plan coordinates for Host request comparison, not authority.
    #[must_use]
    pub fn plan(&self) -> &WorkerPreparationPlanV1 {
        self.preparation.plan()
    }

    /// Borrows only the original ordered plan/FUSE/record/cancellation roles.
    ///
    /// This borrow deliberately does not acknowledge delivery or enable a
    /// challenge. A sender can duplicate these descriptors, so the subsequent
    /// actual session must account for packet/transport/PID1 copies rather
    /// than derive their absence from this type or from a scalar response.
    ///
    /// # Errors
    ///
    /// Rejects a table already moved into its original authenticated transport.
    pub fn launch_roles(&self) -> Result<[BorrowedFd<'_>; 4]> {
        let roles = self
            .roles
            .as_ref()
            .ok_or(MountError::Fence("original worker roles already moved"))?;
        Ok(roles.each_ref().map(|role| role.as_fd()))
    }

    /// Moves the original four owners once while retaining actual Mount custody.
    ///
    /// Taking happens before fallible rechecks. Failure closes these outgoing
    /// copies and cannot recreate the worker endpoint or clear durable escrow.
    /// Returned owners remain transport custody, never connected/read authority.
    ///
    /// # Errors
    ///
    /// Rejects already-moved roles or changed actual owner/object currentness.
    pub fn take_launch_roles(&mut self) -> Result<[OwnedFd; 4]> {
        let roles = self
            .roles
            .take()
            .ok_or(MountError::Fence("original worker roles already moved"))?;
        self.recheck()?;
        Ok(roles)
    }

    /// Borrows the original preparation endpoint after the table has moved.
    ///
    /// This checks the actual held writer and consumed one-shot handoff, not
    /// absence of arbitrary copies made by trusted callers. The closed
    /// security continuation must account for its concrete table/packet/PID1
    /// copies and retain Host's live physical guard before challenging it.
    /// No supplied descriptor, decoded receipt or Boolean can create this
    /// original endpoint or its owning writer.
    ///
    /// # Errors
    ///
    /// Rejects an unmoved table or stale original Mount/object custody.
    #[doc(hidden)]
    pub fn original_worker_channel(
        &mut self,
    ) -> Result<&mut aos_sandbox_linux::seqpacket::SeqpacketSocket> {
        if self.roles.is_some() {
            return Err(MountError::Fence("original worker table has not moved"));
        }
        self.recheck()?;
        Ok(self.preparation.objects.channel_mut())
    }

    /// Rechecks the original actual Mount owner throughout descriptor custody.
    ///
    /// # Errors
    ///
    /// Rejects substituted rows, assignment, scope, namespace or slot. Failure
    /// leaves durable escrow occupied; this type cannot recreate a live worker.
    pub fn recheck(&mut self) -> Result<()> {
        self.preparation.recheck()
    }

    /// Applies the exact retained namespace's idmap under this original writer.
    ///
    /// The actual kernel refuses the original FUSE mount until INIT negotiates
    /// ALLOW_IDMAP with default permissions. A worker record only sequences
    /// this operation; it neither certifies INIT nor grants read authority.
    /// The one-shot durable start marker remains occupied on every failure.
    ///
    /// # Errors
    ///
    /// Rejects unmoved roles, changed owner/objects, absent kernel negotiation,
    /// repeated/ambiguous effect, or a failed post-effect custody readback.
    #[doc(hidden)]
    pub fn apply_original_prepared_idmap(&mut self) -> Result<()> {
        let result = (|| {
            if self.roles.is_some() {
                return Err(MountError::Fence("original worker table has not moved"));
            }
            self.recheck()?;
            self.preparation
                .objects
                .apply_original_user_namespace_idmap()
                .map_err(|error| {
                    MountError::Worker(format!("original worker idmap failed: {error}"))
                })?;
            self.recheck_original_prepared_idmap()
        })();
        if result.is_err() {
            self.preparation.owner.failed = true;
        }
        result
    }

    /// Rechecks actual original idmap-effect custody without repeating IDMAP.
    ///
    /// # Errors
    ///
    /// Rejects changed owner/objects, incomplete effect, or secure-flag failure.
    #[doc(hidden)]
    pub fn recheck_original_prepared_idmap(&mut self) -> Result<()> {
        self.recheck()?;
        let result = self
            .preparation
            .objects
            .recheck_original_user_namespace_idmap_custody()
            .map_err(|error| {
                MountError::Worker(format!("original worker idmap custody failed: {error}"))
            });
        if result.is_err() {
            self.preparation.owner.failed = true;
        }
        result?;
        self.recheck()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_start_commits_the_exact_original_plan_without_minting_custody() {
        let plan = WorkerPreparationPlanV1 {
            worker_instance: [1; 16],
            kernel_boot: [2; 16],
            challenge: [3; 32],
            controller_request: [4; 32],
            mount_reservation: [5; 32],
            assignment: [6; 32],
            attachment: [7; 32],
            original_view_descriptor: [8; 32],
            resolved_policy_descriptor: [9; 32],
            mount_slot: [10; 32],
            ownership_lease: [11; 16],
            ownership_lease_expires_boottime_ns: 300,
            preparation_deadline_boottime_ns: 100,
        };

        let bytes = encode_worker_object_start([5; 32], &plan).unwrap();

        assert_eq!(bytes.len(), 104);
        assert_eq!(&bytes[..8], b"AOSFWC01");
        assert_eq!(&bytes[8..40], &[5; 32]);
        assert_eq!(&bytes[40..56], &plan.worker_instance);
        assert_eq!(&bytes[56..72], &plan.kernel_boot);
        assert_eq!(&bytes[72..], &plan.digest().unwrap());
        assert!(encode_worker_object_start([0; 32], &plan).is_err());

        let transaction_id = worker_object_start_transaction_id([12; 16], &bytes);
        assert_ne!(transaction_id, [0; 16]);
        assert_eq!(
            transaction_id,
            worker_object_start_transaction_id([12; 16], &bytes)
        );
        assert_ne!(
            transaction_id,
            worker_object_start_transaction_id([13; 16], &bytes)
        );
        assert_ne!(
            transaction_id,
            worker_object_start_transaction_id(
                [12; 16],
                &encode_worker_object_start([6; 32], &plan).unwrap()
            )
        );

        let mut changed = plan.clone();
        changed.challenge[0] ^= 1;
        assert_ne!(
            encode_worker_object_start([5; 32], &changed).unwrap(),
            bytes
        );
        assert_ne!(
            transaction_id,
            worker_object_start_transaction_id(
                [12; 16],
                &encode_worker_object_start([5; 32], &changed).unwrap()
            )
        );
        changed = plan.clone();
        changed.resolved_policy_descriptor[0] ^= 1;
        assert_ne!(
            encode_worker_object_start([5; 32], &changed).unwrap(),
            bytes
        );
        changed = plan;
        changed.preparation_deadline_boottime_ns = 301;
        assert!(encode_worker_object_start([5; 32], &changed).is_err());
    }
}
