//! Owns the genuine SQLite issuer above the native host accounting layer.
//!
//! The host exposes only closed original counter custody. Native bootstrap,
//! linked-source qualification and CAS heap authority stay in this daemon.
//! There is one existing account allocation, and no replacement bank or clock.

use crucible::owned_decode::{DecodeAdmissionError, ResourceLoan};
use crucible_cas::content_store::{
    SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessBootstrapAuthority, SqliteProcessHeap,
    StoreError,
};
use crucible_qemu::{
    OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorServicePolicy,
    OriginalGuestServiceHandle, OriginalGuestServiceOwner,
};

mod bootstrap;
pub use bootstrap::OriginalActorSqliteBootstrap;

/// Retains the genuine native issuer beside the same opaque host accounting.
/// No constructor accepts accounts, ceilings or an unrelated original guard.
pub struct OriginalActorSqliteOwner {
    accounts: OriginalGuestServiceOwner,
    actor: OriginalGuestServiceHandle,
    installation_attempted: bool,
}

struct HeapAuthority {
    actor: OriginalGuestServiceHandle,
}

/// Preserves native installation before the independent original postcheck.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorSqliteInstallError {
    /// Actual first native or sticky account error, before its separate original cut.
    #[error("original SQLite installation refused: {source}; original: {original_after:?}")]
    Native {
        /// First native or original admission refusal.
        #[source]
        source: StoreError,
        /// Independent actual guard refusal after native work.
        original_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
    /// Native installation succeeded but the same original subsequently refused.
    #[error("original SQLite post-install boundary refused: {0}")]
    Original(#[source] crucible_linux_resource::host_supervision::HostSupervisionError),
}

/// Retains source-case or kernel refusal before its separate original cut.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorSqliteBootstrapError {
    /// The actual account or original binding refused without formatting.
    #[error(transparent)]
    Account(#[from] OriginalActorAccountError),
    /// The actual kernel page-policy observation refused first.
    #[error("original SQLite kernel policy refused: {source}; original: {original:?}")]
    Kernel {
        /// Actual unmodified kernel observation failure.
        #[source]
        source: std::io::Error,
        /// Independent same-original post-kernel refusal.
        original: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
    /// The actual installed source or native case refused first.
    #[error("original SQLite bootstrap refused: {source}; original: {original:?}")]
    Case {
        /// Existing native issuer or authenticated source-case failure.
        #[source]
        source: StoreError,
        /// Independent same-original boundary after the case check.
        original: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
}

impl OriginalActorSqliteOwner {
    pub(super) fn prepare(
        custody: &OriginalActorAccountCustody,
        policy: OriginalActorServicePolicy,
    ) -> Result<Self, OriginalActorAccountError> {
        let accounts = custody.prepare_guest_service_owner(policy)?;
        let actor = accounts
            .share_accounting()
            .map_err(OriginalActorAccountError::Decode)?;
        Ok(Self {
            accounts,
            actor,
            installation_attempted: false,
        })
    }

    /// Installs the genuine finite heap after the same owner's qualification.
    ///
    /// # Errors
    /// Refuses repeated entry, foreign accounting identity, actual native
    /// initialization or the independent saved-original postcheck.
    pub fn install(
        &mut self,
        bootstrap: OriginalActorSqliteBootstrap,
    ) -> Result<SqliteProcessHeap, OriginalActorSqliteInstallError> {
        let result = self.install_inner(bootstrap);
        let after = self.actor.original_check();
        match (result, after) {
            (Err(source), after) => Err(OriginalActorSqliteInstallError::Native {
                source,
                original_after: after.err(),
            }),
            (Ok(heap), Ok(())) => Ok(heap),
            (Ok(heap), Err(source)) => {
                std::mem::forget(heap);
                Err(OriginalActorSqliteInstallError::Original(source))
            }
        }
    }

    fn install_inner(
        &mut self,
        bootstrap: OriginalActorSqliteBootstrap,
    ) -> Result<SqliteProcessHeap, StoreError> {
        if self.installation_attempted {
            return Err(StoreError::Unauthorized);
        }
        self.installation_attempted = true;
        verify(&self.actor)?;
        bootstrap.verify_actor(&self.accounts)?;
        SqliteProcessHeap::prepare_bootstrap(self)?;
        let controls = self
            .actor
            .reserve_metadata(SqliteHeapIssuer::control_bytes::<HeapAuthority>())
            .map_err(admission)?;
        let issuer = SqliteHeapIssuer::new(
            HeapAuthority {
                actor: self.accounts.share_accounting().map_err(admission)?,
            },
            controls,
        );
        SqliteProcessHeap::install(issuer, self.actor.heap_bytes(), self.accounts.connections())
    }
}

impl SqliteHeapAuthority for HeapAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        verify(&self.actor)
    }
    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.reserve_heap(bytes).map_err(admission)
    }
    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.reserve_metadata(bytes).map_err(admission)
    }
}

impl SqliteProcessBootstrapAuthority for OriginalActorSqliteOwner {
    fn verify_live(&self) -> Result<(), StoreError> {
        verify(&self.actor)
    }
    fn reserve_bootstrap(&self, rust_metadata_bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor
            .reserve_bootstrap(rust_metadata_bytes)
            .map_err(admission)
    }
}

fn verify(actor: &OriginalGuestServiceHandle) -> Result<(), StoreError> {
    actor.verify_live().map_err(admission)
}
fn admission(source: DecodeAdmissionError) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: None,
    }
}
