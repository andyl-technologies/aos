//! Retains the normal Source-funded fixed credentials and genuine055 Origins.
//!
//! All native inputs remain with this original on refusal. Only a completed
//! assembly moves its actual credentials into the same existing Origins type;
//! the full signed schema and native history engine choose the normal branch
//! from this private custody, never a decoded mode or caller-supplied flag.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::runtime_deployment::boot_preparation::BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1;

use super::super::genesis::BootGenesisAssemblyV1;
use super::super::{
    RuntimeBootPreparationStartupClosedV1, RuntimeBootPreparationStartupOriginalV1,
};
use super::*;

#[derive(Clone, Copy)]
enum First {
    Startup,
    Funding(usize),
    Credentials,
    Assembly,
    Post,
    Order,
}

/// Refuses normal credential admission while the original retains every cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("normal BootPreparation055 origins are incomplete or refused")]
pub struct RuntimeBootPreparationOriginsClosedV1;

/// Retains the actual Source loan, fixed credentials and complete normal genesis.
///
/// Construction charges the same Source before creating the resident carrier.
/// No descriptor, purpose bytes, mode, path or replacement vector can construct
/// these Origins. Admission alone grants neither signing nor physical work.
#[must_use = "retain this whole original through every independently owed post"]
pub struct RuntimeBootPreparationOriginsOriginalV1<'startup> {
    startup: &'startup RuntimeBootPreparationStartupOriginalV1,
    credentials: Option<RuntimeDeploymentCredentialCustodyV2>,
    assembly: Option<Result<BootGenesisAssemblyV1<'startup>, NvCustodyErrorV1>>,
    origins: Option<RuntimeDeploymentComparisonOriginsV1<'startup>>,
    startup_result: Option<Result<(), RuntimeBootPreparationStartupClosedV1>>,
    funding: [Option<Result<(), RuntimeBootPreparationStartupClosedV1>>; 2],
    post_result: Option<Result<(), RuntimeBootPreparationStartupClosedV1>>,
    first: Option<First>,
    attempted: bool,
    ready: bool,
}

impl<'startup> RuntimeBootPreparationOriginsOriginalV1<'startup> {
    /// Prepays empty normal055 custody on the actual unfinished Source.
    ///
    /// # Errors
    /// Refuses absent positive startup, checked geometry or exhausted same-M
    /// receiving. No native file has been opened by this constructor.
    pub fn new(
        startup: &'startup RuntimeBootPreparationStartupOriginalV1,
    ) -> Result<Self, RuntimeBootPreparationStartupClosedV1> {
        let demand = (|| {
            let carriers = std::mem::size_of::<Self>().checked_mul(2)?;
            // Two full source inputs dominate the two canonical signature
            // preimages and complete composite Vec backing. Fixed key/model
            // carriers are already present in the compiled owner layout.
            let input = BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1.checked_mul(4)?;
            Some(ResourceVector::ZERO.with(
                D::MemoryBytes,
                u64::try_from(carriers.checked_add(input)?).ok()?,
            ))
        })();
        startup.fund_additional(demand)?;
        Ok(Self {
            startup,
            credentials: None,
            assembly: None,
            origins: None,
            startup_result: None,
            funding: [None, None],
            post_result: None,
            first: None,
            attempted: false,
            ready: false,
        })
    }

    /// Captures the exact normal delivery and joins its signed contracts once.
    ///
    /// # Errors
    /// Retains startup, funding, credential, signature, profile and final-post
    /// refusal. Reentry cannot reopen files, replace an original or retry.
    pub fn admit_once_v1(&mut self) -> Result<(), RuntimeBootPreparationOriginsClosedV1> {
        if self.attempted || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(RuntimeBootPreparationOriginsClosedV1);
        }
        self.attempted = true;
        let result = self.admit_body();
        // This Source currentness lane owns its own prepaid independent posts.
        // It is invoked separately from the body result; final Source after is
        // still owed by the process owner after055 and publication have ended.
        self.post_result = Some(self.startup.require_current_v1());
        if !matches!(self.post_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Post);
        }
        if result.is_err() || self.first.is_some() {
            return Err(RuntimeBootPreparationOriginsClosedV1);
        }
        let assembly = match self.assembly.take() {
            Some(Ok(assembly)) => assembly,
            original => {
                self.assembly = original;
                return self.fail(First::Order);
            }
        };
        let Some(credentials) = self.credentials.take() else {
            // This invariant follows from the successful body. Never drop a
            // completed assembly containing secret/original state on refusal.
            std::process::abort();
        };
        self.origins = Some(RuntimeDeploymentComparisonOriginsV1 {
            genesis: assembly.into_original(credentials),
        });
        self.ready = true;
        Ok(())
    }

    fn admit_body(&mut self) -> Result<(), RuntimeBootPreparationOriginsClosedV1> {
        self.startup_result = Some(self.startup.require_current_v1());
        if !matches!(self.startup_result, Some(Ok(()))) {
            return self.fail(First::Startup);
        }
        self.funding[0] = Some(self.startup.fund_additional(
            RuntimeDeploymentCredentialCustodyV2::boot_preparation_receiving_demand_v1(),
        ));
        if !matches!(self.funding[0], Some(Ok(()))) { return self.fail(First::Funding(0)); }
        self.credentials = Some(RuntimeDeploymentCredentialCustodyV2::new_boot_preparation_v1());
        if self
            .credentials
            .as_mut()
            .ok_or(RuntimeBootPreparationOriginsClosedV1)?
            .capture()
            .is_err()
        {
            return self.fail(First::Credentials);
        }
        self.assembly = Some(BootGenesisAssemblyV1::decode(
            self.startup,
            self.credentials
                .as_ref()
                .ok_or(RuntimeBootPreparationOriginsClosedV1)?,
        ));
        if !matches!(self.assembly, Some(Ok(_))) {
            return self.fail(First::Assembly);
        }
        self.funding[1] = Some(self.startup.fund_additional(
            RuntimeDeploymentCredentialCustodyV2::boot_preparation_receiving_demand_v1(),
        ));
        if !matches!(self.funding[1], Some(Ok(()))) { return self.fail(First::Funding(1)); }
        if self
            .credentials
            .as_mut()
            .ok_or(RuntimeBootPreparationOriginsClosedV1)?
            .recheck()
            .is_err()
        {
            return self.fail(First::Credentials);
        }
        Ok(())
    }

    fn fail(&mut self, first: First) -> Result<(), RuntimeBootPreparationOriginsClosedV1> {
        self.first.get_or_insert(first);
        Err(RuntimeBootPreparationOriginsClosedV1)
    }

    /// Borrows only the completed same-original055 comparison owner.
    #[must_use]
    pub fn origins_v1(&self) -> Option<&RuntimeDeploymentComparisonOriginsV1<'startup>> {
        if self.ready && self.first.is_none() {
            self.origins.as_ref()
        } else {
            None
        }
    }

    /// Borrows the actual first retained failure without moving an input owner.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Funding(index) => self.funding.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Credentials => self.credentials.as_ref()?.failure().map(|cause| cause as _),
            First::Assembly => self
                .assembly
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Startup => self
                .startup_result
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Post => self
                .post_result
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Order => None,
        }
    }

    /// Formats the same retained Source cause for funding or startup refusal.
    ///
    /// The borrowed view enters no RefCell/native work until formatting, and
    /// cannot outlive or move the actual Source or credential originals.
    #[must_use]
    pub fn failure_view_v1(&self) -> impl std::fmt::Display + '_ {
        OriginsFailureView(self)
    }
}

struct OriginsFailureView<'owner, 'startup>(&'owner RuntimeBootPreparationOriginsOriginalV1<'startup>);

impl std::fmt::Display for OriginsFailureView<'_, '_> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.first {
            Some(First::Startup | First::Funding(_) | First::Post) => {
                write!(output, "{}", self.0.startup.failure_view_v1())
            }
            _ => match self.0.failure_v1() {
                Some(cause) => write!(output, "{cause}"),
                None => output.write_str("normal Origins are incomplete or refused"),
            },
        }
    }
}
