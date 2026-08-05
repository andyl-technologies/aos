//! Shared white-box doorbell instruction ABI.
//!
//! The ABI defines only the architecture-specific trap instruction and register
//! contract. The architecture-independent frame carried by the doorbell is owned
//! by the guest-host channel spec and decoded by the plugin.

/// Version of the architecture-specific doorbell instruction ABI.
pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = 3;
/// Reserved x86_64 port used by the canonical white-box doorbell ABI.
pub const WHITEBOX_DOORBELL_X86_64_RESERVED_PORT: u16 = 0x00e7;
/// Reserved aarch64 immediate used by the canonical white-box doorbell ABI.
pub const WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE: u16 = 0x04c1;
/// Frozen x86_64 trap instruction bytes for `out 0xe7, al`.
pub const WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES: [u8; 2] =
    encode_x86_64_out_imm8_al_instruction(WHITEBOX_DOORBELL_X86_64_RESERVED_PORT as u8);
/// Frozen aarch64 trap instruction bytes for `hlt #0x04c1`.
pub const WHITEBOX_DOORBELL_AARCH64_HLT_BYTES: [u8; 4] =
    encode_aarch64_hlt_instruction(WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE);
/// Canonical x86_64 doorbell ABI entry used by plugin and guest code.
pub const WHITEBOX_DOORBELL_X86_64_ABI: WhiteboxDoorbellAbi = WhiteboxDoorbellAbi {
    version: WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
    architecture: WhiteboxDoorbellArchitecture::X86_64,
    instruction: WhiteboxDoorbellInstruction::X86OutImm8Al,
    trap: WhiteboxDoorbellTrapAbi::X86PortIo {
        port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
    },
    payload_pointer_register: "rax",
    payload_length_register: "rcx",
    assembly: "out 0xe7, al",
    instruction_bytes: &WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
    vector_name: "x86_64-out-imm8-al-port-e7",
};
/// Canonical aarch64 doorbell ABI entry used by plugin and guest code.
pub const WHITEBOX_DOORBELL_AARCH64_ABI: WhiteboxDoorbellAbi = WhiteboxDoorbellAbi {
    version: WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
    architecture: WhiteboxDoorbellArchitecture::Aarch64,
    instruction: WhiteboxDoorbellInstruction::Aarch64Hlt,
    trap: WhiteboxDoorbellTrapAbi::Aarch64Hlt {
        immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
    },
    payload_pointer_register: "x0",
    payload_length_register: "x1",
    assembly: "hlt #0x04c1",
    instruction_bytes: &WHITEBOX_DOORBELL_AARCH64_HLT_BYTES,
    vector_name: "aarch64-hlt-imm-04c1",
};
/// All canonical doorbell ABI entries in stable golden-vector order.
pub const WHITEBOX_DOORBELL_ABIS: &[WhiteboxDoorbellAbi] =
    &[WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_AARCH64_ABI];

/// A supported architecture for the white-box doorbell instruction ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellArchitecture {
    /// x86-64 guest machine architecture.
    X86_64,
    /// AArch64 guest machine architecture.
    Aarch64,
}

impl WhiteboxDoorbellArchitecture {
    /// Returns the stable ABI spelling for this architecture.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// The precise trapped instruction selected by a doorbell ABI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellInstruction {
    /// x86-64 `out imm8, al` with the reserved port encoded in the instruction.
    X86OutImm8Al,
    /// AArch64 `hlt #imm16`.
    Aarch64Hlt,
}

impl WhiteboxDoorbellInstruction {
    /// Returns the stable ABI spelling for this instruction.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86OutImm8Al => "out-imm8-al",
            Self::Aarch64Hlt => "hlt-imm16",
        }
    }
}

/// The architecture-specific trap surface represented by an ABI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellTrapAbi {
    /// x86_64 reserved port-I/O write.
    X86PortIo {
        /// Reserved port number chosen by the ABI.
        port: u16,
    },
    /// AArch64 reserved `hlt #imm16` instruction.
    Aarch64Hlt {
        /// Reserved immediate encoded in the trap instruction.
        immediate: u16,
    },
}

/// One canonical architecture-specific doorbell ABI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellAbi {
    version: u16,
    architecture: WhiteboxDoorbellArchitecture,
    instruction: WhiteboxDoorbellInstruction,
    trap: WhiteboxDoorbellTrapAbi,
    payload_pointer_register: &'static str,
    payload_length_register: &'static str,
    assembly: &'static str,
    instruction_bytes: &'static [u8],
    vector_name: &'static str,
}

impl WhiteboxDoorbellAbi {
    /// Returns the ABI version that owns this entry.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Returns the guest architecture for this ABI entry.
    #[must_use]
    pub const fn architecture(self) -> WhiteboxDoorbellArchitecture {
        self.architecture
    }

    /// Returns the precise trapped instruction kind.
    #[must_use]
    pub const fn instruction(self) -> WhiteboxDoorbellInstruction {
        self.instruction
    }

    /// Returns the trap surface derived from this ABI entry.
    #[must_use]
    pub const fn trap(self) -> WhiteboxDoorbellTrapAbi {
        self.trap
    }

    /// Returns the guest register that carries the payload pointer.
    #[must_use]
    pub const fn payload_pointer_register(self) -> &'static str {
        self.payload_pointer_register
    }

    /// Returns the guest register that carries the payload length.
    #[must_use]
    pub const fn payload_length_register(self) -> &'static str {
        self.payload_length_register
    }

    /// Returns the canonical assembly spelling of the trapped instruction.
    #[must_use]
    pub const fn assembly(self) -> &'static str {
        self.assembly
    }

    /// Returns the frozen trap instruction bytes in guest memory byte order.
    #[must_use]
    pub const fn instruction_bytes(self) -> &'static [u8] {
        self.instruction_bytes
    }

    /// Returns the stable golden-vector name for this ABI entry.
    #[must_use]
    pub const fn vector_name(self) -> &'static str {
        self.vector_name
    }
}

/// Returns the canonical doorbell ABI entry for an architecture.
#[must_use]
pub const fn whitebox_doorbell_abi_for_architecture(
    architecture: WhiteboxDoorbellArchitecture,
) -> WhiteboxDoorbellAbi {
    match architecture {
        WhiteboxDoorbellArchitecture::X86_64 => WHITEBOX_DOORBELL_X86_64_ABI,
        WhiteboxDoorbellArchitecture::Aarch64 => WHITEBOX_DOORBELL_AARCH64_ABI,
    }
}

/// Encodes the x86_64 `out imm8, al` trap instruction.
#[must_use]
pub const fn encode_x86_64_out_imm8_al_instruction(port: u8) -> [u8; 2] {
    [0xe6, port]
}

/// Encodes the aarch64 `hlt #imm16` trap instruction as little-endian bytes.
#[must_use]
pub const fn encode_aarch64_hlt_instruction(immediate: u16) -> [u8; 4] {
    let word = 0xd440_0000_u32 | ((immediate as u32) << 5);
    [
        (word & 0xff) as u8,
        ((word >> 8) & 0xff) as u8,
        ((word >> 16) & 0xff) as u8,
        ((word >> 24) & 0xff) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doorbell_abi_vectors_cover_x86_64_and_aarch64() {
        assert_eq!(WHITEBOX_DOORBELL_ABIS.len(), 2);
        assert_eq!(
            WHITEBOX_DOORBELL_ABIS
                .iter()
                .map(|abi| abi.vector_name())
                .collect::<Vec<_>>(),
            vec!["x86_64-out-imm8-al-port-e7", "aarch64-hlt-imm-04c1"]
        );
        assert_eq!(
            whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::X86_64),
            WHITEBOX_DOORBELL_X86_64_ABI
        );
        assert_eq!(
            whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::Aarch64),
            WHITEBOX_DOORBELL_AARCH64_ABI
        );
    }

    #[test]
    fn doorbell_abi_x86_64_vector_freezes_out_imm8_al() {
        let abi = WHITEBOX_DOORBELL_X86_64_ABI;

        assert_eq!(abi.version(), WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION);
        assert_eq!(abi.architecture().as_str(), "x86_64");
        assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::X86OutImm8Al);
        assert_eq!(
            abi.trap(),
            WhiteboxDoorbellTrapAbi::X86PortIo {
                port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
            }
        );
        assert_eq!(abi.payload_pointer_register(), "rax");
        assert_eq!(abi.payload_length_register(), "rcx");
        assert_eq!(
            encode_x86_64_out_imm8_al_instruction(WHITEBOX_DOORBELL_X86_64_RESERVED_PORT as u8),
            WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES
        );
        assert_eq!(abi.instruction_bytes(), &[0xe6, 0xe7]);
    }

    #[test]
    fn doorbell_abi_aarch64_vector_freezes_hlt_immediate() {
        let abi = WHITEBOX_DOORBELL_AARCH64_ABI;

        assert_eq!(abi.version(), WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION);
        assert_eq!(abi.architecture().as_str(), "aarch64");
        assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::Aarch64Hlt);
        assert_eq!(
            abi.trap(),
            WhiteboxDoorbellTrapAbi::Aarch64Hlt {
                immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
            }
        );
        assert_eq!(abi.payload_pointer_register(), "x0");
        assert_eq!(abi.payload_length_register(), "x1");
        assert_eq!(
            encode_aarch64_hlt_instruction(WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE),
            WHITEBOX_DOORBELL_AARCH64_HLT_BYTES
        );
        assert_eq!(abi.instruction_bytes(), &[0x20, 0x98, 0x40, 0xd4]);
    }
}
