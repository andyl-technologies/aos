//! Encodes the closed Network V2 negative correlation record.
//!
//! ```text
//! AOSNERR2 | version:u16 | kind:u8 | reserved:u8 | total:u32 |
//! request16 | effect32 | plan32 | boot16 | namespace16 |
//! cause:u16 | phase:u16 | reserved12 | diagnostic16
//! ```
//!
//! Decoding yields DATA only. The actual failed native/financial originals,
//! acknowledgement, leader death and Empty/Retired disposition remain owed
//! on the enclosing worker owners. This record creates no permission or retry.
//! Bootstrap precedes READY and the plan handoff: only that closed phase uses
//! zero plan/namespace fields to mean unknown, rather than inventing identities
//! or entering unpaid native work after a failed F/Source gate.

use super::*;

pub(crate) const NETWORK_WORKER_NEGATIVE_BYTES_V2: usize = 160;

const MAGIC: &[u8; 8] = b"AOSNERR2";
const VERSION: u16 = 2;
const NEGATIVE_KIND: u8 = 2;

/// Classifies the original refusal without transporting its sensitive details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkWorkerFailureCauseV2 {
    Funding = 1,
    Native = 2,
    Clock = 3,
    Authority = 4,
    Protocol = 5,
    Source = 6,
}

impl NetworkWorkerFailureCauseV2 {
    fn decode(code: u16) -> Result<Self, NetworkWorkerProcessError> {
        match code {
            1 => Ok(Self::Funding),
            2 => Ok(Self::Native),
            3 => Ok(Self::Clock),
            4 => Ok(Self::Authority),
            5 => Ok(Self::Protocol),
            6 => Ok(Self::Source),
            _ => protocol("negative cause is unsupported"),
        }
    }

    // Exact, closed diagnostics disclose neither errno text nor private paths.
    const fn diagnostic(self) -> [u8; 16] {
        match self {
            Self::Funding => *b"FUNDING\0\0\0\0\0\0\0\0\0",
            Self::Native => *b"NATIVE\0\0\0\0\0\0\0\0\0\0",
            Self::Clock => *b"CLOCK\0\0\0\0\0\0\0\0\0\0\0",
            Self::Authority => *b"AUTHORITY\0\0\0\0\0\0\0",
            Self::Protocol => *b"PROTOCOL\0\0\0\0\0\0\0\0",
            Self::Source => *b"SOURCE\0\0\0\0\0\0\0\0\0\0",
        }
    }
}

/// Identifies the finite entered frontier, without authorizing its completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkWorkerFailurePhaseV2 {
    Bootstrap = 1,
    Admission = 2,
    Preparation = 3,
    Observation = 4,
    Handback = 5,
}

impl NetworkWorkerFailurePhaseV2 {
    fn decode(code: u16) -> Result<Self, NetworkWorkerProcessError> {
        match code {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Admission),
            3 => Ok(Self::Preparation),
            4 => Ok(Self::Observation),
            5 => Ok(Self::Handback),
            _ => protocol("negative phase is unsupported"),
        }
    }
}

/// Correlates a failed attempt while its genuine owners retain the first cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkWorkerNegativeV2 {
    correlation: Correlation,
    cause: NetworkWorkerFailureCauseV2,
    phase: NetworkWorkerFailurePhaseV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Correlation {
    Bootstrap { request: [u8; 16], effect: ObjectDigest, boot: [u8; 16] },
    Admission { request: [u8; 16], effect: ObjectDigest, boot: [u8; 16], namespace: NamespaceIdentity },
    Complete(NetworkWorkerResultV1),
}

impl NetworkWorkerNegativeV2 {
    /// Constructs bounded comparison DATA from an already established identity.
    pub(crate) fn new(
        correlation: NetworkWorkerResultV1,
        cause: NetworkWorkerFailureCauseV2,
        phase: NetworkWorkerFailurePhaseV2,
    ) -> Result<Self, NetworkWorkerProcessError> {
        if phase == NetworkWorkerFailurePhaseV2::Bootstrap {
            return protocol("bootstrap has no captured plan or namespace");
        }
        Ok(Self { correlation: Correlation::Complete(correlation), cause, phase })
    }

    /// Constructs only negative comparison DATA from an authenticated prebirth.
    ///
    /// Zero plan/namespace explicitly mean unknown. This does not authorize
    /// native capture, adopt the input as Source authority or assert a result.
    pub(crate) fn bootstrap_data(
        request: [u8; 16], effect: ObjectDigest, boot: [u8; 16],
        cause: NetworkWorkerFailureCauseV2,
    ) -> Result<Self, NetworkWorkerProcessError> {
        if request == [0; 16] || effect.as_bytes() == &[0; 32] || boot == [0; 16] {
            return protocol("bootstrap correlation contains a reserved identity");
        }
        Ok(Self { correlation: Correlation::Bootstrap { request, effect, boot },
            cause, phase: NetworkWorkerFailurePhaseV2::Bootstrap })
    }

    /// Constructs a refusal before a plan is authenticated, after real READY.
    ///
    /// The namespace remains the actual captured identity. The zero plan SHA
    /// explicitly means unknown and cannot become a positive result or D.
    pub(crate) fn admission_data(
        request: [u8; 16], effect: ObjectDigest, boot: [u8; 16],
        namespace: NamespaceIdentity, cause: NetworkWorkerFailureCauseV2,
    ) -> Result<Self, NetworkWorkerProcessError> {
        Self::bootstrap_data(request, effect, boot, cause)?;
        if namespace.device == 0 || namespace.inode == 0 {
            return protocol("admission negative has no actual namespace identity");
        }
        Ok(Self { correlation: Correlation::Admission { request, effect, boot, namespace },
            cause, phase: NetworkWorkerFailurePhaseV2::Admission })
    }

    pub(crate) const fn correlation(self) -> Option<NetworkWorkerResultV1> {
        match self.correlation { Correlation::Complete(value) => Some(value), _ => None }
    }

    pub(crate) const fn request_id(self) -> [u8; 16] {
        match self.correlation {
            Correlation::Complete(value) => value.request_id,
            Correlation::Bootstrap { request, .. } | Correlation::Admission { request, .. } => request,
        }
    }

    pub(crate) const fn effect_digest(self) -> ObjectDigest {
        match self.correlation {
            Correlation::Complete(value) => value.effect_digest,
            Correlation::Bootstrap { effect, .. } | Correlation::Admission { effect, .. } => effect,
        }
    }

    pub(crate) const fn kernel_boot_id(self) -> [u8; 16] {
        match self.correlation {
            Correlation::Complete(value) => value.kernel_boot_id,
            Correlation::Bootstrap { boot, .. } | Correlation::Admission { boot, .. } => boot,
        }
    }

    pub(crate) const fn cause(self) -> NetworkWorkerFailureCauseV2 {
        self.cause
    }

    /// Borrows only the namespace coordinate actually present in the negative.
    pub(crate) const fn namespace_data_v2(self) -> Option<NamespaceIdentity> {
        match self.correlation {
            Correlation::Bootstrap { .. } => None,
            Correlation::Admission { namespace, .. } => Some(namespace),
            Correlation::Complete(value) => Some(value.namespace()),
        }
    }

    pub(crate) const fn phase(self) -> NetworkWorkerFailurePhaseV2 {
        self.phase
    }

    pub(crate) fn encode(self) -> [u8; NETWORK_WORKER_NEGATIVE_BYTES_V2] {
        let mut bytes = [0; NETWORK_WORKER_NEGATIVE_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = NEGATIVE_KIND;
        bytes[12..16].copy_from_slice(&(NETWORK_WORKER_NEGATIVE_BYTES_V2 as u32).to_be_bytes());
        bytes[16..32].copy_from_slice(&self.request_id());
        bytes[32..64].copy_from_slice(self.effect_digest().as_bytes());
        bytes[96..112].copy_from_slice(&self.kernel_boot_id());
        if let Correlation::Complete(value) = self.correlation {
            bytes[64..96].copy_from_slice(value.kernel_plan_digest.as_bytes());
            bytes[112..120].copy_from_slice(&value.namespace.device.to_be_bytes());
            bytes[120..128].copy_from_slice(&value.namespace.inode.to_be_bytes());
        }
        if let Correlation::Admission { namespace, .. } = self.correlation {
            bytes[112..120].copy_from_slice(&namespace.device.to_be_bytes());
            bytes[120..128].copy_from_slice(&namespace.inode.to_be_bytes());
        }
        bytes[128..130].copy_from_slice(&(self.cause as u16).to_be_bytes());
        bytes[130..132].copy_from_slice(&(self.phase as u16).to_be_bytes());
        bytes[144..].copy_from_slice(&self.cause.diagnostic());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        if bytes.len() != NETWORK_WORKER_NEGATIVE_BYTES_V2 {
            return protocol("negative length is invalid");
        }
        let mut decoder = BoundedReader::new(bytes, read_error);
        if decoder.array::<8>()? != *MAGIC
            || decoder.u16()? != VERSION
            || decoder.u8()? != NEGATIVE_KIND
            || decoder.u8()? != 0
            || decoder.u32()? != NETWORK_WORKER_NEGATIVE_BYTES_V2 as u32
        {
            return protocol("negative header is invalid");
        }
        let request = decoder.array()?;
        let effect = ObjectDigest::from_bytes(decoder.array()?);
        let plan = ObjectDigest::from_bytes(decoder.array()?);
        let boot = decoder.array()?;
        let namespace = NamespaceIdentity { device: decoder.u64()?, inode: decoder.u64()? };
        let cause = NetworkWorkerFailureCauseV2::decode(decoder.u16()?)?;
        let phase = NetworkWorkerFailurePhaseV2::decode(decoder.u16()?)?;
        if decoder.array::<12>()? != [0; 12]
            || decoder.array::<16>()? != cause.diagnostic()
        {
            return protocol("negative reserved or diagnostic bytes differ");
        }
        decoder.finish()?;
        if phase == NetworkWorkerFailurePhaseV2::Bootstrap {
            if plan.as_bytes() != &[0; 32] || namespace.device != 0 || namespace.inode != 0 {
                return protocol("bootstrap negative invents a plan or namespace identity");
            }
            Self::bootstrap_data(request, effect, boot, cause)
        } else if phase == NetworkWorkerFailurePhaseV2::Admission && plan.as_bytes() == &[0; 32] {
            Self::admission_data(request, effect, boot, namespace, cause)
        } else {
            let correlation = NetworkWorkerResultV1::new(request, effect, plan, boot, namespace)?;
            Self::new(correlation, cause, phase)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure() -> NetworkWorkerNegativeV2 {
        let correlation = NetworkWorkerResultV1::new(
            [1; 16], ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]), [4; 16],
            NamespaceIdentity { device: 5, inode: 6 },
        ).unwrap();
        NetworkWorkerNegativeV2::new(correlation,
            NetworkWorkerFailureCauseV2::Funding,
            NetworkWorkerFailurePhaseV2::Preparation).unwrap()
    }

    #[test]
    fn negative_is_exact_and_does_not_enter_the_positive_parser() {
        let failure = failure();
        let encoded = failure.encode();

        assert_eq!(NetworkWorkerNegativeV2::decode(&encoded).unwrap(), failure);
        assert!(NetworkWorkerResultV1::decode(&encoded).is_err());
        assert!(NetworkWorkerNegativeV2::decode(&failure.correlation().unwrap().encode()).is_err());
        for length in 0..encoded.len() {
            assert!(NetworkWorkerNegativeV2::decode(&encoded[..length]).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(NetworkWorkerNegativeV2::decode(&extended).is_err());
    }

    #[test]
    fn negative_refuses_old_headers_unknown_codes_and_noncanonical_diagnostics() {
        let encoded = failure().encode();
        for position in [7, 8, 9, 10, 11, 12, 15, 128, 130, 132, 143, 144, 159] {
            let mut changed = encoded;
            changed[position] ^= 0x80;
            assert!(NetworkWorkerNegativeV2::decode(&changed).is_err());
        }
        let mut old = encoded;
        old[..8].copy_from_slice(b"AOSNERR1");
        assert!(NetworkWorkerNegativeV2::decode(&old).is_err());
    }

    #[test]
    fn bootstrap_unknowns_do_not_invent_a_plan_namespace_or_positive_result() {
        let bootstrap = NetworkWorkerNegativeV2::bootstrap_data([1; 16],
            ObjectDigest::from_bytes([2; 32]), [4; 16], NetworkWorkerFailureCauseV2::Source).unwrap();
        let bytes = bootstrap.encode();

        assert_eq!(NetworkWorkerNegativeV2::decode(&bytes).unwrap(), bootstrap);
        assert_eq!(&bytes[64..96], &[0; 32]);
        assert_eq!(&bytes[112..128], &[0; 16]);
        assert!(bootstrap.correlation().is_none());
        assert!(NetworkWorkerResultV1::decode(&bytes).is_err());
        for offset in (64..96).chain(112..128) {
            let mut invented = bytes;
            invented[offset] = 1;
            assert!(NetworkWorkerNegativeV2::decode(&invented).is_err());
        }
        let complete = failure().correlation().unwrap();
        assert!(NetworkWorkerNegativeV2::new(complete, NetworkWorkerFailureCauseV2::Source,
            NetworkWorkerFailurePhaseV2::Bootstrap).is_err());
    }

    #[test]
    fn unadmitted_plan_has_only_the_real_ready_namespace_and_cannot_reach_effect_phase() {
        let failure = NetworkWorkerNegativeV2::admission_data([1; 16],
            ObjectDigest::from_bytes([2; 32]), [4; 16],
            NamespaceIdentity { device: 5, inode: 6 }, NetworkWorkerFailureCauseV2::Authority).unwrap();
        let bytes = failure.encode();

        assert_eq!(NetworkWorkerNegativeV2::decode(&bytes).unwrap(), failure);
        assert_eq!(&bytes[64..96], &[0; 32]);
        assert!(failure.correlation().is_none());
        let mut effect = bytes;
        effect[130..132].copy_from_slice(&(NetworkWorkerFailurePhaseV2::Preparation as u16).to_be_bytes());
        assert!(NetworkWorkerNegativeV2::decode(&effect).is_err());
        let mut unknown_namespace = bytes;
        unknown_namespace[112..128].fill(0);
        assert!(NetworkWorkerNegativeV2::decode(&unknown_namespace).is_err());
    }
}
