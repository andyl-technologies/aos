//! Drives the original packet collection owner with both publishers retained.
//!
//! Each poll performs at most one lifecycle phase. The capsule owns its native
//! runtime, exact token/cases and both durable publishers across callback errors
//! and unwind. The runner stays owned through collection; its consuming, local
//! finalization moves reports into the completed result. An interrupted finalizer
//! remains failed while complete original report/native bodies stay in the
//! independently retained source and report store. No runtime or mutable
//! publisher/runner getter is exposed.

use std::task::{Context, Poll};

use crucible::node_adapters::cnp::CnpSemanticSource;
use crucible::node_contract::{ActivationPublisher, ConformanceResultPublisher};

use super::{
    InstalledPacketCollectionAuthority, PacketCollectionFailure, PacketCollectionLifecycle,
    PacketCollectionPhase,
};
use crate::node_qualification::{
    CollectedConformance, ProductionConformanceRunner, QualificationError, QualificationLimits,
};

/// Retains the complete caller and publishers when actor installation refuses.
pub struct PacketExecutionInstallationFailure<A, R> {
    /// Describes the original finite/current-scope refusal.
    pub error: QualificationError,
    _lifecycle: PacketCollectionLifecycle,
    _activation: A,
    _result: R,
}

/// Owns the actual packet caller, original collector and both durable publishers.
///
/// A returned failure never retires native custody or starts another peer. The
/// caller must keep this capsule outside its unwind guard and retain the actual
/// runtime supervisor until genuine native reclamation. Settled is data-only
/// progress; complete unexecuted normative obligations still prevent acceptance.
#[must_use = "retain the actual execution and its original custody supervisor"]
pub struct PacketCollectionExecution<'a, A, R> {
    lifecycle: PacketCollectionLifecycle,
    runner: Option<ProductionConformanceRunner<'a>>,
    activation: A,
    result: R,
    maximum_record_bytes: usize,
    collected: Option<CollectedConformance>,
    report_finalization_failed: bool,
}

impl InstalledPacketCollectionAuthority {
    /// Owns the exact original lifecycle and independently installed collector.
    ///
    /// # Errors
    /// Retains all supplied owners on a foreign original plan, changed current
    /// source, missing complete population or invalid finite record credit.
    pub fn execution<'a, A: ActivationPublisher, R: ConformanceResultPublisher>(
        &'a self,
        lifecycle: PacketCollectionLifecycle,
        activation: A,
        result: R,
        limits: QualificationLimits,
        maximum_record_bytes: usize,
    ) -> Result<PacketCollectionExecution<'a, A, R>, Box<PacketExecutionInstallationFailure<A, R>>>
    {
        let checked = (|| {
            if maximum_record_bytes == 0
                || maximum_record_bytes > 65_536
                || lifecycle
                    .original_plan()
                    .authenticate_authority(self)
                    .is_err()
            {
                return Err(QualificationError::Refused(
                    "packet execution original plan or coordinator credit",
                ));
            }
            self.current()?;
            ProductionConformanceRunner::new(
                self,
                self.source.installation().descriptor.id.clone(),
                self.source
                    .installation()
                    .binding
                    .compatibility
                    .identity()?,
                &self.plan_bytes,
                &self.plan_reference,
                limits,
            )
        })();
        let runner = match checked {
            Ok(runner) => runner,
            Err(error) => {
                return Err(Box::new(PacketExecutionInstallationFailure {
                    error,
                    _lifecycle: lifecycle,
                    _activation: activation,
                    _result: result,
                }));
            }
        };
        Ok(PacketCollectionExecution {
            lifecycle,
            runner: Some(runner),
            activation,
            result,
            maximum_record_bytes,
            collected: None,
            report_finalization_failed: false,
        })
    }
}

impl<A: ActivationPublisher, R: ConformanceResultPublisher> PacketCollectionExecution<'_, A, R> {
    /// Drives one actual phase without replacing the original owner or operation.
    ///
    /// # Errors
    /// Returns the original lifecycle refusal or uncertainty with every owner
    /// retained. Publishing retries only the same original durability/ACK path;
    /// Held has no redispatch path. Unwind preserves this capsule in its caller.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketCollectionFailure>> {
        if self.report_finalization_failed {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        }
        let step = match self.lifecycle.phase() {
            PacketCollectionPhase::Prepared => self.lifecycle.arm(),
            PacketCollectionPhase::Armed => self
                .lifecycle
                .activate_initial(&mut self.activation, self.maximum_record_bytes),
            PacketCollectionPhase::Active => self.lifecycle.begin(),
            PacketCollectionPhase::Pending => match self.lifecycle.poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Ok(()),
            },
            PacketCollectionPhase::Complete => {
                let Some(runner) = self.runner.as_mut() else {
                    return Poll::Ready(Err(PacketCollectionFailure::Phase));
                };
                self.lifecycle.collect_before_ack(runner)
            }
            PacketCollectionPhase::Collected | PacketCollectionPhase::Publishing => {
                self.lifecycle.publish_and_acknowledge(&mut self.result)
            }
            PacketCollectionPhase::Acknowledged => {
                let Some(runner) = self.runner.as_mut() else {
                    return Poll::Ready(Err(PacketCollectionFailure::Phase));
                };
                self.lifecycle.collect_after_ack(runner)
            }
            PacketCollectionPhase::Settled => {
                if let Some(runner) = self.runner.take() {
                    // Native bodies also remain under the original source and
                    // report-store custody. This complete report keeps unknown
                    // obligations explicit; it is not ordinary acceptance.
                    self.report_finalization_failed = true;
                    self.collected = Some(runner.finish());
                    self.report_finalization_failed = false;
                }
                return Poll::Ready(Ok(()));
            }
            PacketCollectionPhase::Held => {
                return Poll::Ready(Err(PacketCollectionFailure::Phase));
            }
        };
        if let Err(error) = step {
            return Poll::Ready(Err(error));
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    /// Borrows complete retained observations without issuing accepted authority.
    pub fn collected(&self) -> Option<&CollectedConformance> {
        self.collected.as_ref()
    }

    /// Reports the same original lifecycle's data-only progress.
    pub fn phase(&self) -> PacketCollectionPhase {
        self.lifecycle.phase()
    }
}
