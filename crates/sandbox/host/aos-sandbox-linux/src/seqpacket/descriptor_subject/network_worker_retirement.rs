//! Keeps completed Network record DATA after its automatic subject proof retires.
//!
//! The enclosing actor must complete every actual Source/native/semantic post
//! first. This consuming operation retains the same payload, socket-origin
//! stamp and original credential/process scalars. The returned DATA has no
//! native subject API and cannot recreate a record, Source or effect loan.

use super::{ReceivedDescriptorRecord, ReceivedSocketOrigin};
use aos_linux_descriptors::pidfd::PidFdInfo;
use crate::seqpacket::RecordCredentials;

/// Retains a completed closed Network record without a live subject capability.
#[derive(Debug)]
pub struct NetworkWorkerRetiredRecordDataV2 {
    payload: Vec<u8>,
    _origin: ReceivedSocketOrigin,
    credentials: RecordCredentials,
    initial_info: PidFdInfo,
}

impl NetworkWorkerRetiredRecordDataV2 {
    /// Borrows the original packet bytes without creating native authority.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the original nominated credential scalars as comparison DATA.
    #[must_use]
    pub const fn credentials_data_v2(&self) -> RecordCredentials {
        self.credentials
    }

    /// Returns the original pidfd information without a new process query.
    #[must_use]
    pub const fn initial_info_data_v2(&self) -> PidFdInfo {
        self.initial_info
    }
}

impl ReceivedDescriptorRecord {
    /// Moves the first P frame's exact native namespace carriers as DATA.
    ///
    /// The caller first authenticates Source, complete frame grammar and the
    /// distinct63-host1 or9-target/host2 role. Payload, original subject and
    /// socket stamp stay on this original for independent posts. This creates
    /// no namespace authority or claimed-fence supplier.
    #[must_use]
    pub fn take_network_preparation_frame_descriptors_data_v3(
        &mut self,
    ) -> Option<Vec<std::os::fd::OwnedFd>> {
        let bytes = &self.payload;
        if !(57..=65536).contains(&bytes.len()) || &bytes[..8] != b"AOSNFRM2"
            || bytes[8..10] != 2_u16.to_be_bytes()
            || u16::from_be_bytes(bytes[10..12].try_into().ok()?) & 1 == 0
            || !matches!(self.descriptors.len(), 1 | 2) {
            return None;
        }
        Some(std::mem::take(&mut self.descriptors))
    }

    /// Moves only the exact O host/target pair while keeping its record resident.
    ///
    /// The entire request must separately equal the admitted handoff section,
    /// and Source/native/semantic posts remain owed. These structural checks
    /// adopt no namespace, signed request, currentness or effect authority.
    #[must_use]
    pub fn take_network_observer_namespace_descriptors_data_v2(
        &mut self,
    ) -> Option<Vec<std::os::fd::OwnedFd>> {
        let bytes = &self.payload;
        if !(184..=184 + 512 * 1024).contains(&bytes.len())
            || &bytes[..8] != b"AOSNORQ2" || bytes[8..12] != [0, 2, 2, 0]
            || bytes[129..132] != [0; 3] || self.descriptors.len() != 2 {
            return None;
        }
        let total = usize::try_from(u32::from_be_bytes(bytes[12..16].try_into().ok()?)).ok()?;
        let plan = usize::try_from(u32::from_be_bytes(bytes[180..184].try_into().ok()?)).ok()?;
        if total != bytes.len() || 184usize.checked_add(plan) != Some(total) { return None; }
        Some(std::mem::take(&mut self.descriptors))
    }

    /// Retires only a positively completed closed Network subject proof.
    ///
    /// The caller completes transport, Source, native and semantic posts before
    /// consuming this original. No transferred right may remain. Only PFrame2,
    /// the fixed H03 header and ACK2 have this mechanical disposition; their
    /// original bytes and identity DATA remain continuously owned. Failed or
    /// partial originals must remain on the caller unchanged. No fee, native
    /// peak or prior financial debit is refunded.
    ///
    /// # Errors
    /// Returns the complete unchanged original for another shape or any right
    /// that the genuine enclosing owner has not already taken into custody.
    pub fn retire_network_worker_positive_subject_data_v2(
        self,
    ) -> Result<NetworkWorkerRetiredRecordDataV2, Self> {
        if !self.descriptors.is_empty() || !closed_retirable_shape(&self.payload) {
            return Err(self);
        }
        let credentials = self.subject.credentials();
        let initial_info = self.subject.initial_info();
        let Self { payload, subject, descriptors, origin } = self;
        drop(subject);
        drop(descriptors);
        Ok(NetworkWorkerRetiredRecordDataV2 {
            payload,
            _origin: origin,
            credentials,
            initial_info,
        })
    }
}

fn closed_retirable_shape(bytes: &[u8]) -> bool {
    match bytes.len() {
        10 => &bytes[..8] == b"AOSNACK2" && bytes[8..10] == 2_u16.to_be_bytes(),
        528 if &bytes[..8] == b"AOSNOH03" => {
            bytes[8..12] == [0, 3, 0, 2] && bytes[188..192] == [0; 4]
        }
        57..=65536 => &bytes[..8] == b"AOSNFRM2" && bytes[8..10] == 2_u16.to_be_bytes(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::closed_retirable_shape;

    #[test]
    fn completed_proof_disposition_has_only_the_new_closed_wire_shapes() {
        let mut ack = *b"AOSNACK2\0\x02";
        assert!(closed_retirable_shape(&ack));
        ack[7] = b'1';
        assert!(!closed_retirable_shape(&ack));

        let mut header = [0; 528];
        header[..8].copy_from_slice(b"AOSNOH03");
        header[8..12].copy_from_slice(&[0, 3, 0, 2]);
        assert!(closed_retirable_shape(&header));
        header[188] = 1;
        assert!(!closed_retirable_shape(&header));

        let mut frame = [0; 57];
        frame[..8].copy_from_slice(b"AOSNFRM2");
        frame[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(closed_retirable_shape(&frame));
        frame[7] = b'1';
        assert!(!closed_retirable_shape(&frame));
    }
}
