//! Encodes one readonly Candidate worker request and its two actual machine rows.
//!
//! This private format carries a validated managed root and immutable deadline;
//! it contains no raw command selector, Capture lifetime or mutation operation.
//!
//! ```text
//! AOSCPF01 | cutoff:u64 | executable:u16+bytes | pool:u16+utf8
//!          | root:u16+utf8 | guid:u64
//! rows = pool-length:u32 | pool-bytes | root-length:u32 | root-bytes
//! ```

use super::*;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsPreflightPlanV1, capture_preflight_commands_v1,
};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

const MAGIC: &[u8; 8] = b"AOSCPF01";

pub(super) struct CandidatePreflightRequestV1 {
    pub(super) executable: PathBuf,
    pub(super) root: crate::ManagedDatasetRoot,
    pub(super) cutoff: u64,
}

pub(super) fn is_request(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZfsWorkerError> {
    let length = u16::try_from(bytes.len())
        .map_err(|_| ZfsWorkerError::Protocol("candidate preflight field is too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn construction_bytes_v1(
    contract: &ZfsHelperContract,
    plan: &CaptureZfsPreflightPlanV1,
) -> Option<usize> {
    8usize
        .checked_add(8 + 2 + 2 + 2 + 8)?
        .checked_add(contract.executable().as_os_str().as_bytes().len())?
        .checked_add(plan.root_data_v1().pool().len())?
        .checked_add(plan.root_data_v1().dataset_prefix().len())
}

pub(super) fn encode_request_into(
    contract: &ZfsHelperContract,
    plan: &CaptureZfsPreflightPlanV1,
    cutoff: u64,
    output: &mut Vec<u8>,
) -> Result<(), ZfsWorkerError> {
    if cutoff == 0 || !output.is_empty() {
        return Err(ZfsWorkerError::Authority);
    }
    let bound = construction_bytes_v1(contract, plan).ok_or(ZfsWorkerError::Authority)?;
    if bound > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Authority);
    }
    output
        .try_reserve_exact(bound)
        .map_err(|_| ZfsWorkerError::Protocol("candidate preflight allocation failed"))?;
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&cutoff.to_be_bytes());
    put_bytes(output, contract.executable().as_os_str().as_bytes())?;
    put_bytes(output, plan.root_data_v1().pool().as_bytes())?;
    put_bytes(output, plan.root_data_v1().dataset_prefix().as_bytes())?;
    output.extend_from_slice(&plan.root_data_v1().guid().to_be_bytes());
    Ok(())
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<CandidatePreflightRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Authority);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != MAGIC {
        return Err(ZfsWorkerError::Authority);
    }
    let cutoff = decoder.u64()?;
    if cutoff == 0 {
        return Err(ZfsWorkerError::Authority);
    }
    let length = usize::from(decoder.u16()?);
    let executable = PathBuf::from(OsString::from_vec(decoder.take(length)?.to_vec()));
    let length = usize::from(decoder.u16()?);
    let pool = std::str::from_utf8(decoder.take(length)?).map_err(|_| ZfsWorkerError::Authority)?;
    let length = usize::from(decoder.u16()?);
    let prefix =
        std::str::from_utf8(decoder.take(length)?).map_err(|_| ZfsWorkerError::Authority)?;
    let guid = decoder.u64()?;
    decoder.finish()?;
    let root = crate::ManagedDatasetRoot::from_catalog(pool, prefix, guid)
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok(CandidatePreflightRequestV1 {
        executable,
        root,
        cutoff,
    })
}

pub(super) fn encode_rows(outputs: &[Vec<u8>; 2]) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    let length = outputs
        .iter()
        .try_fold(8usize, |sum, row| {
            if row.len() > MAXIMUM_MACHINE_OUTPUT_BYTES {
                return None;
            }
            sum.checked_add(row.len())
        })
        .ok_or(ZfsWorkerError::Authority)?;
    let mut stdout = Vec::with_capacity(length);
    for row in outputs {
        stdout.extend_from_slice(
            &u32::try_from(row.len())
                .map_err(|_| ZfsWorkerError::Authority)?
                .to_be_bytes(),
        );
        stdout.extend_from_slice(row);
    }
    Ok(WorkerProcessOutput {
        stdout,
        stderr: Vec::new(),
        success: true,
        timed_out: false,
    })
}

pub(super) fn decode_rows(output: &WorkerProcessOutput) -> Result<[&[u8]; 2], ZfsWorkerError> {
    if !output.success || output.timed_out || !output.stderr.is_empty() {
        return Err(ZfsWorkerError::Authority);
    }
    let mut decoder = Decoder::new(&output.stdout);
    let first = usize::try_from(decoder.u32()?).map_err(|_| ZfsWorkerError::Authority)?;
    if first > MAXIMUM_MACHINE_OUTPUT_BYTES {
        return Err(ZfsWorkerError::Authority);
    }
    let first = decoder.take(first)?;
    let second = usize::try_from(decoder.u32()?).map_err(|_| ZfsWorkerError::Authority)?;
    if second > MAXIMUM_MACHINE_OUTPUT_BYTES {
        return Err(ZfsWorkerError::Authority);
    }
    let second = decoder.take(second)?;
    decoder.finish()?;
    Ok([first, second])
}

// Every native receiver precedes the execution scope: a failure is printed and
// terminates while these original fields and actual kernel owners stay resident.
pub(super) fn run_worker_v1(
    entry: &mut worker_entry::WorkerEntryOriginalV3,
    aggregate: &mut worker_aggregate::WorkerAggregateV1,
) -> Result<(), ZfsWorkerError> {
    use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
    use aos_sandbox_linux::seqpacket::bounded::{
        ZfsWorkerRecordKindV1, ZfsWorkerSendKindV1, receive_zfs_worker_record_v1,
        send_zfs_worker_record_v1,
    };
    let entry_deadline = entry.deadline.ok_or(ZfsWorkerError::Authority)?;
    let Some(worker_entry::CaptureEntryLoansV3 {
        parent,
        socket,
        contract,
        path,
    }) = entry.borrow_capture_entry_v3()
    else {
        return Err(worker_entry::retained());
    };
    // This borrower is the existing mechanical held parent/Session split.
    // It carries no60 lifetime; this exact readonly magic is required here.
    if !is_request(parent.request_v3().payload()) {
        return Err(ZfsWorkerError::Authority);
    }
    let decoded = Some(decode_request(parent.request_v3().payload()));
    let mut observation = CaptureZfsObservationOriginalV3::new();
    let mut observed = None;
    let mut response = None;
    let mut encoded = None;
    let mut sent = None;
    let mut ack = None;
    let mut subject = None;
    let mut membership = ExactCgroupMembershipReadbackV1::new();
    let mut membership_result = None;
    let mut ack_decode = None;
    let selection = (|| {
        let Some(Ok(request)) = decoded.as_ref() else { return Err(worker_entry::retained()); };
        if request.executable != *contract.executable() { return Err(ZfsWorkerError::Authority); }
        let cutoff = entry_deadline.absolute_nanoseconds_v3()?.min(request.cutoff);
        Deadline(Duration::from_nanos(cutoff)).ensure_pending()?;
        Ok(cutoff)
    })();
    let cutoff = match &selection {
        Ok(cutoff) => *cutoff,
        Err(cause) => {
            // A failed decode/association precedes any execution-scope entry.
            // Print its actual source while the held parent/packet and every
            // already reached native entry original are still resident.
            let original = decoded.as_ref().and_then(|result| result.as_ref().err()).unwrap_or(cause);
            eprintln!("candidate worker retained selection failure: {original}");
            std::process::abort();
        }
    };
    let mut execution = aggregate.borrow_execution_scope_v1(path)?;
    let result = (|| {
        let Some(Ok(request)) = decoded.as_ref() else { return Err(worker_entry::retained()); };
        let commands = capture_preflight_commands_v1(&request.root);
        observed = Some(run_capture_zfs_observation_commands_with_scope_v3(
            contract,
            &commands,
            Some(&mut observation),
            Some((&mut execution, cutoff)),
        ));
        let Some(Ok(outputs)) = observed.as_ref() else {
            return Err(worker_entry::retained());
        };
        response = Some(encode_rows(outputs));
        let Some(Ok(output)) = response.as_ref() else {
            return Err(worker_entry::retained());
        };
        encoded = Some(encode_mutation_response(output));
        let Some(Ok(bytes)) = encoded.as_ref() else {
            return Err(worker_entry::retained());
        };
        // These fixed two rows are <=8200 bytes and use the same zero-rights
        // retained send recipe already used for the native Capture reports.
        sent = Some(send_zfs_worker_record_v1(
            socket,
            bytes,
            ZfsWorkerSendKindV1::Request,
            cutoff,
        ));
        if sent.as_ref().is_none_or(|attempt| !attempt.is_sent()) {
            return Err(worker_entry::retained());
        }
        ack = Some(receive_zfs_worker_record_v1(
            socket,
            ZfsWorkerRecordKindV1::Acknowledgement,
            cutoff,
        ));
        let Some(Ok(received)) = ack.as_ref() else {
            return Err(worker_entry::retained());
        };
        subject = Some(verify_same_live_subject(
            parent.request_v3().subject(),
            received.subject(),
        ));
        if !matches!(subject, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        membership_result =
            Some(membership.capture_once(parent.parent_v3(), received.subject().pidfd()));
        if !matches!(membership_result, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        ack_decode = Some(decode_ack(received.payload()));
        if !matches!(ack_decode, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        observation.retire_positive()?;
        Ok(())
    })();
    if let Err(cause) = result {
        let original = execution
            .failure_v3()
            .or_else(|| observation.failure())
            .or_else(|| {
                decoded
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                observed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                response
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                encoded
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| sent.as_ref()?.failure())
            .or_else(|| {
                ack.as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                subject
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                membership
                    .failure()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                ack_decode
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as &dyn std::error::Error)
            });
        if let Some(original) = original {
            eprintln!("candidate worker retained failure: {original}");
        } else {
            eprintln!("candidate worker retained failure: {cause}");
        }
        std::process::abort();
    }
    execution.complete_after_ack_v1();
    Ok(())
}

// All these reservoirs precede scope construction/native entry above.
pub(super) fn receiving_bytes_v1(
    contract: &ZfsHelperContract,
    plan: &CaptureZfsPreflightPlanV1,
) -> Option<usize> {
    use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
    use aos_sandbox_linux::seqpacket::bounded::{
        ZfsWorkerRecordKindV1, ZfsWorkerSendAttemptV1, zfs_worker_record_obligations_v1,
    };
    let machine = 2usize.checked_mul(MAXIMUM_MACHINE_OUTPUT_BYTES)?;
    let framed = machine.checked_add(8)?;
    let encoded = framed.checked_add(20)?;
    let types = std::mem::size_of::<Result<u64, ZfsWorkerError>>()
        .checked_add(std::mem::size_of::<CandidatePreflightRequestV1>())?
        .checked_add(std::mem::size_of::<WorkerProcessOutput>())?
        .checked_add(std::mem::size_of::<ZfsWorkerSendAttemptV1>())?
        .checked_add(std::mem::size_of::<[Vec<u8>; 2]>())?;
    types
        .checked_add(
            CaptureZfsObservationOriginalV3::representation_commands_bytes_v1(
                contract,
                plan.commands(),
            )?,
        )?
        .checked_add(machine)?
        .checked_add(framed)?
        .checked_add(encoded)?
        .checked_add(zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::Acknowledgement)?.0)?
        .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_bytes(cutoff: u64) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&cutoff.to_be_bytes());
        put_bytes(&mut bytes, b"/fixed/store/zfs").unwrap();
        put_bytes(&mut bytes, b"tank").unwrap();
        put_bytes(&mut bytes, b"tank/managed").unwrap();
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes
    }

    #[test]
    fn readonly_capsule_refuses_zero_horizon_foreign_magic_and_trailing_bytes() {
        let original = request_bytes(17);
        let decoded = decode_request(&original).unwrap();
        assert_eq!(decoded.cutoff, 17);
        assert_eq!(decoded.root.dataset_prefix(), "tank/managed");

        assert!(decode_request(&request_bytes(0)).is_err());
        let mut foreign = original.clone();
        foreign[..8].copy_from_slice(b"AOSXYZ01");
        assert!(decode_request(&foreign).is_err());
        let mut trailing = original;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn rows_require_exact_two_bounded_successful_machine_outputs() {
        let mut output = encode_rows(&[b"pool-row".to_vec(), b"root-row".to_vec()]).unwrap();
        assert_eq!(
            decode_rows(&output).unwrap(),
            [b"pool-row".as_slice(), b"root-row".as_slice()]
        );

        output.stdout.push(0);
        assert!(decode_rows(&output).is_err());
        output.stdout.pop();
        output.success = false;
        assert!(decode_rows(&output).is_err());
        assert!(encode_rows(&[vec![0; MAXIMUM_MACHINE_OUTPUT_BYTES + 1], Vec::new()]).is_err());
    }
}
