//! Projects fixed startup credential failures without rebuilding native causes.
//!
//! Existing mechanical/native/append/financial categories keep their original
//! upper classes. New retained markers stay attached to this same startup owner.

use super::{
    CacheReadbackPinErrorV1, ControllerHoldPinErrorV1, PolicyDeploymentHeadErrorV1,
    SourceHoldPinErrorV1,
};
use crate::journal::JournalError;
use aos_sandbox_policy::native::{
    PolicyNativeJournalErrorV1 as Native, RootStartupCredentialErrorV1 as Credential,
    RootStartupJournalErrorV1 as Startup,
};

// A lexical error recipe avoids a second owning result or intermediate wrapper.
// Every actual native enum class is named; no future class silently flattens.
macro_rules! project_credential_error {
    ($upper:ty, [$($flag:ident),+], [$($other:ident),+]) => {
        impl From<Credential> for $upper {
            fn from(error: Credential) -> Self {
                match error {
                    $(Credential::$flag => Self::$flag,)+
                    Credential::Native(Native::Mechanical(cause))
                    | Credential::Startup(Startup::Native(Native::Mechanical(cause))) =>
                        Self::Journal(JournalError::from(cause)),
                    Credential::Native(Native::Root(cause))
                    | Credential::Startup(Startup::Native(Native::Root(cause))) =>
                        Self::Journal(JournalError::RootNative(cause)),
                    Credential::Native(Native::RootAppend(cause))
                    | Credential::Startup(Startup::Native(Native::RootAppend(cause))) =>
                        Self::Journal(JournalError::RootAppendOriginal(cause)),
                    Credential::Native(Native::Financial(cause))
                    | Credential::Startup(Startup::Native(Native::Financial(cause))) =>
                        Self::Journal(JournalError::RootFinancial(cause)),
                    original @ (
                        $(Credential::$other |)+
                        Credential::Opening { .. }
                        | Credential::Startup(Startup::Names | Startup::Closed)
                        | Credential::Native(Native::Q04Current(_) | Native::TargetCurrent(_) | Native::NativePost(_))
                        | Credential::Startup(Startup::Native(Native::Q04Current(_) | Native::TargetCurrent(_) | Native::NativePost(_)))
                    ) => Self::NativeStartup(original),
                }
            }
        }
    };
}

project_credential_error!(
    PolicyDeploymentHeadErrorV1,
    [InvalidHead, InvalidSignature, StaleHead],
    [InvalidPin, StalePin]
);
project_credential_error!(
    CacheReadbackPinErrorV1,
    [InvalidPin, StalePin],
    [InvalidHead, InvalidSignature, StaleHead]
);
project_credential_error!(
    ControllerHoldPinErrorV1,
    [InvalidPin, StalePin],
    [InvalidHead, InvalidSignature, StaleHead]
);
project_credential_error!(
    SourceHoldPinErrorV1,
    [InvalidPin, StalePin],
    [InvalidHead, InvalidSignature, StaleHead]
);
