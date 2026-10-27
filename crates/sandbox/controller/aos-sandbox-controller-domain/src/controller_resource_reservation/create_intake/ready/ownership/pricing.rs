//! Derives only this closed client's actual reached representation bounds.
//!
//! The same J owns the financial account. These recipes accept neither a
//! ceiling nor a caller-built vector; every attempt remains cumulatively paid.
//! The shared HistoryNames peak is borrowed through the actual fixed entrance;
//! only its newly resident backing/metadata is added to this client's debt.

use std::mem::size_of;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector, ObjectDescriptor, OwnershipLease};
use aos_sandbox_model::model::{KeyReference, Signature};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_ownership_protocol::protocol::{MAXIMUM_OWNERSHIP_REQUEST_BYTES,
    MAXIMUM_OWNERSHIP_RESPONSE_BYTES};
use super::*;

pub(super) fn credential_demand_v1() -> Option<ResourceVector> {
    credential_representation_demand_v1(true)
}

pub(super) fn credential_representation_demand_v1(create_samples: bool) -> Option<ResourceVector> {
    use aos_sandbox_ownership_protocol::trusted_policy::OwnershipTrustConfigurationCaptureV1;
    let policy = credentials::MAXIMUM_POLICY_BYTES;
    // The same retained constructor prices both actual canonical policy parses,
    // their reached key/feature/constructor destinations and move temporaries.
    // The fixed credential readers retain separate raw bytes/path backing.
    let directory = std::path::Path::new("/run/credentials/aos-sandboxd.service");
    let mut joined_paths = 0_usize;
    for name in ["ownership-session-key", "ownership-lease-policy.cbor", "ownership-lease-public-key"] {
        joined_paths = joined_paths.max(aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
            joined_path_receiving_bytes_v1(directory, name)?);
    }
    let bytes = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(policy)?
        .checked_add(joined_paths)?
        .checked_add(policy)?.checked_add(3 * 4096 + 4 * 32)?;
    let metadata = OwnershipTrustConfigurationCaptureV1::receiving_metadata_cells_v1(policy)?
        .checked_add(7)?;
    let samples = if create_samples { sample_backing_v1()? } else { ResourceVector::ZERO };
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        // Each retained fixed reader owns its real leaf. Six slots also cover
        // the shared reader's actual directory-open/leaf overlap on refusal.
        .with(D::OpenFiles, 6).with(D::MetadataEntries, u64::try_from(metadata).ok()?)
        .checked_add(samples).ok()
}

pub(super) fn complete_demand_v1(
    attempts: usize, verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Option<ResourceVector> {
    let credentials = credential_demand_v1()?;
    let flight = flight_demand_v1(verifier)?;
    let mut result = credentials;
    for dimension in D::ALL {
        result = result.with(dimension, credentials.get(dimension)
            .checked_add(flight.get(dimension).checked_mul(u64::try_from(attempts).ok()?)?)?);
    }
    Some(result)
}

fn sample_backing_v1() -> Option<ResourceVector> {
    CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2).ok()
}

fn flight_demand_v1(
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Option<ResourceVector> {
    flight_representation_demand_v1(verifier, true)?.checked_add(flight_traffic_demand_v1()?).ok()
}

pub(super) fn flight_representation_demand_v1(
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    create_samples: bool,
) -> Option<ResourceVector> {
    let request = usize::try_from(MAXIMUM_OWNERSHIP_REQUEST_BYTES).ok()?;
    let response = usize::try_from(MAXIMUM_OWNERSHIP_RESPONSE_BYTES).ok()?;
    let (record_bytes, record_files) = SeqpacketSocket::local_ownership_receive_obligations_v1(response)?;
    let (connect_bytes, connect_files) = SeqpacketSocket::retained_connect_obligations_v1();
    // HELLO and three semantic records remain together through the independent
    // post and socket ending, including a malformed final ancillary interval.
    let receive = record_bytes.checked_mul(4)?;
    // This exact retained verifier derives its actual private policy extent.
    // The fixed outer response bound dominates its contained artifact quartet;
    // all partial policy/lease/signature/receipt models coexist with transport.
    let verification_bytes =
        verifier.response_receiving_dynamic_bytes_v2(response)?;
    let receive_files = record_files.checked_mul(4)?.checked_add(connect_files)?;
    // Three raw responses, independently decoded artifacts and the consumed
    // verifier copy coexist. Eight full encoded artifact lanes cover those
    // buffers plus MAC/canonical re-encoding scratch; requests retain three
    // complete canonical/encoded lanes. The separate verification supplier
    // prices both actual trust-policy parses and all deeper retained models.
    // try_reserve_exact grows a Vec of whole flights. Previous resident cells
    // and its new allocation can overlap; three requested cells per retained
    // flight dominate old + new carriers without assuming in-place realloc.
    // Heap fields below remain separately charged for every live attempt.
    let flight_carriers = size_of::<OwnershipFlightV1>().checked_mul(3)?;
    let bytes = flight_carriers.checked_add(connect_bytes)?
        .checked_add(receive)?.checked_add(response.checked_mul(8)?)?
        .checked_add(request.checked_mul(6)?)?.checked_add(verification_bytes)?
        .checked_add(4 * (size_of::<Signature>() + size_of::<OwnershipLease>()
            + size_of::<ObjectDescriptor>() + size_of::<KeyReference>() + 4 * 255))?;
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, u64::try_from(receive_files).ok()?)
        .with(D::MetadataEntries, u64::try_from(receive_files.checked_add(1)?).ok()?)
        .checked_add(aos_sandbox_broker::paired_clock::PairedClockSamplesV1::receiving_demand_v1()?).ok()?
        .checked_add(if create_samples { sample_backing_v1()? } else { ResourceVector::ZERO }).ok()
}

pub(super) fn flight_traffic_demand_v1() -> Option<ResourceVector> {
    let request = usize::try_from(MAXIMUM_OWNERSHIP_REQUEST_BYTES).ok()?;
    let response = usize::try_from(MAXIMUM_OWNERSHIP_RESPONSE_BYTES).ok()?;
    let traffic = u64::try_from(3usize.checked_mul(request.checked_add(response)?)?
        .checked_add(2 * MAXIMUM_OWNERSHIP_HELLO_BYTES)?).ok()?;
    let output = u64::try_from(3usize.checked_mul(request)?
        .checked_add(MAXIMUM_OWNERSHIP_HELLO_BYTES)?).ok()?;
    Some(ResourceVector::ZERO.with(D::NetworkBytes, traffic).with(D::OutputBytes, output))
}
