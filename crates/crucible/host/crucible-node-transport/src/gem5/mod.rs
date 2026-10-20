//! Authenticated native gem5 control beneath the common CNP custody journal.
//!
//! The private driver retains actual pre-event receipts and process-image
//! lineage. Native boundary mechanics do not qualify a complete CPU/device
//! profile: public exact admission requires installed clock/input qualification
//! and independently authenticated complete native custody. Complete modeled
//! diagnostics and audited whole-process capture are distinct proof mechanisms;
//! partial diagnostic coverage never becomes a claim of complete typed state.

mod images;
mod journal;
mod process;
mod protocol;
pub mod service;

pub use images::*;
pub use journal::*;
pub use process::*;
pub use protocol::*;

#[cfg(test)]
mod tests;

mod arm_root_installed;
mod arm_root_launch;
pub use arm_root_installed::InstalledArmRootMechanism;
pub use arm_root_launch::ArmRootLaunch;

mod arm_root_group;
mod arm_root_process;
mod model;
mod refusal;
pub use arm_root_process::{
    ArmRootCustodySlot, ArmRootHostLedger, ArmRootNativeCustody, ArmRootNativeProcess,
    ArmRootPreparedSession,
};
pub use model::{
    Gem5ArmNativeReady, Gem5ConfigurationTree, Gem5ModelAsset, Gem5ModelDialect,
    Gem5ModelSelection, Gem5SerialPublication,
};

mod arm_root_capture;
pub use arm_root_capture::{ArmRootCapturedImage, ArmRootPrefix, ArmRootRunOutcome};

mod arm_root_closure;
pub use arm_root_closure::ArmRootProcessClosure;

mod arm_root_exact;
pub use arm_root_exact::ArmRootExactAuthority;

mod arm_root_run;

mod arm_root_restore;
pub use arm_root_restore::ArmRootRestoreTarget;

pub use refusal::{
    Gem5DiagnosticCreditPolicy, Gem5RefusalAcknowledgement, Gem5RefusalCredit, Gem5RunRefusal,
    ParsedGem5RunRefusal, parse_run_refusal, parse_run_refusal_for_model,
    validate_refusal_acknowledgement,
};

mod arm_root_budget;

mod arm_root_io;

mod arm_root_history;
pub use arm_root_history::{
    ArmRootControlHistory, ArmRootControlKind, ArmRootControlPacket, ArmRootPreparationRecord,
};

mod arm_root_source;
pub use arm_root_source::ArmRootHistoricalSource;
pub use images::arm_root_archive::{ArmRootArchiveImport, ArmRootArchiveSourceVerifier};

mod x86_root_capture;
mod x86_root_closure;
mod x86_root_exact;
mod x86_root_history;
mod x86_root_installed;
mod x86_root_launch;
mod x86_root_model;
mod x86_root_process;
mod x86_root_restore;
mod x86_root_run;
mod x86_root_source;

pub use images::x86_root_archive::{X86RootArchiveImport, X86RootArchiveSourceVerifier};
pub use x86_root_capture::{X86RootCapturedImage, X86RootPrefix, X86RootRunOutcome};
pub use x86_root_closure::X86RootProcessClosure;
pub use x86_root_exact::X86RootExactAuthority;
pub use x86_root_history::{
    X86RootControlHistory, X86RootControlKind, X86RootControlPacket, X86RootPreparationRecord,
};
pub use x86_root_installed::InstalledX86RootModel;
pub use x86_root_launch::X86RootLaunch;
pub use x86_root_model::{Gem5X86RootNativeAssets, Gem5X86RootNativeReady, Gem5X86RootNativeScope};
pub use x86_root_process::{
    X86RootCustodySlot, X86RootHostLedger, X86RootNativeCustody, X86RootNativeProcess,
    X86RootPreparedSession,
};
pub use x86_root_restore::X86RootRestoreTarget;
pub use x86_root_source::X86RootHistoricalSource;

mod native_command;
pub use native_command::{NativeCommandConstructionBudget, NativeCommandConstructionPolicy};

mod installed_qualification;
