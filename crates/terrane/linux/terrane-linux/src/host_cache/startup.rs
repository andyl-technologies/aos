//! Records closed startup phases without changing native errors or recovery policy.
//!
//! These observations contain no paths, domain names, credentials or source
//! text. Callers retain the original I/O error; a stage never grants authority
//! or controls a fallback, retry or recovery decision.

/// Identifies the last attempted group of native startup checks or effects.
#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeCacheStartupStage {
    Configuration,
    Confinement,
    QuotaConnect,
    QuotaPartition,
    NativeBinding,
    PortableBeforeRecovery,
    ProcessIdentity,
    NativeLayout,
    ContentCustody,
    QuotaObservation,
    PublisherConnect,
    PublisherDrain,
    PublisherSealProbe,
    SealVerification,
    PortableCatalog,
    MetadataReader,
    OwnerStart,
    Recovery,
    PublisherResume,
    PortableAfterRecovery,
    FinalCustody,
    PortableCheckpoint,
    ContentStore,
}
