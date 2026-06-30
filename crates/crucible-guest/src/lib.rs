//! `crucible-guest` owns the optional in-guest white-box agent.
//!
//! Spec index: RFC-0010 files 16.
//!
//! This L2 crate will contain the additive doorbell client described by
//! its indexed RFC-0010 file. It is never required for core black-box operation
//! and is an unsafe-boundary crate because future code may issue trapped guest
//! instructions and touch ABI memory directly.
//!
//! Module map: the crate root currently reserves the optional guest-agent
//! boundary and re-exports the shared doorbell instruction ABI; future modules
//! will split doorbell transport from guest ABI accessors.
//!
//! Unsafe boundary discipline: trapped-instruction and ABI-memory details stay
//! private; public callers use safe doorbell and marker accessors that uphold
//! guest/register and shared-region invariants.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use crucible_protocol::{
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HLT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WHITEBOX_DOORBELL_X86_64_ABI,
    WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES, WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
    WhiteboxDoorbellAbi, WhiteboxDoorbellArchitecture, WhiteboxDoorbellInstruction,
    WhiteboxDoorbellTrapAbi, encode_aarch64_hlt_instruction, encode_x86_64_out_dx_eax_instruction,
    whitebox_doorbell_abi_for_architecture,
};
