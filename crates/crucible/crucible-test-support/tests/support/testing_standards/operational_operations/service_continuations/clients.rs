//! Binds replay and reproduction clients to original Main-owned retirement.
//!
//! Local aliases close before their recorded receiver acknowledgment. Actual
//! terminal custody and raw refusals remain independent of the outer result.

use super::Contract;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_baked_genesis/supervised_replay",
        required: &[
            (
                r###"if !self.body_closed {
            self.body_closed = self.service.retry_prepared_body().map_err(|raw| {
                ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure_with_refusal("close replay native body", raw),
                    post: self.post,
                    progress: None,
                }
            })?;
            if !self.body_closed {
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self.service.failure("replay native body remains retained"),
                    post: self.post,
                    progress: None,
                });
            }
        }"###,
                1,
            ),
            (
                r###"if let Some(original) = self.operation.take() {
            self.post = original.complete().err();
        }
        self.dispose_aliases();
        if let Some(receiver) = self.receiver.take() {
            receiver.return_after_alias_destruction().map_err(|raw| {
                ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure_with_refusal("acknowledge replay alias destruction", raw),
                    post: self.post,
                    progress: None,
                }
            })?;
        }"###,
                1,
            ),
            (
                r###"match progress {
            Ok(true) => {}
            progress => {
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure("replay World or Service return remains retained"),
                    post: self.post,
                    progress: progress.err(),
                });
            }
        }
        let Some(retirement) = self.retirement.take() else {
            return Err(ProductionReplayCleanup::Prepared {
                failure: self.service.failure("same replay retirement disappeared"),
                post: self.post,
                progress: None,
            });
        };
        let body = match retirement.finish() {
            Ok(body) => body,
            Err(retirement) => {
                self.retirement = Some(retirement);
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure("replay terminal payload remains borrowed"),
                    post: self.post,
                    progress: None,
                });
            }
        };
        self.finished = true;
        if body.first_failure().is_some() || self.post.is_some() {
            return Err(ProductionReplayCleanup::Returned {
                body,
                post: self.post,
            });
        }
        drop(body);
        Ok(())"###,
                1,
            ),
            (
                r###"let retirement = self .retirement .get_or_insert_with(|| self.prepared.clone().into_retirement());"###,
                1,
            ),
            (
                r###"fn dispose_aliases(&mut self) { self.registration = None; self.source = None; self.supervisor = None; }"###,
                1,
            ),
        ],
        expressions: &[
            ("self.service.retry_prepared_body()", 1),
            ("retirement.retry()", 1),
        ],
        identifiers: &[("retry_prepared_body", 1), ("retry", 1)],
        companions: super::SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/tests/paging_native/main_service",
        required: &[
            (
                r###"fn from_ready(role: ServiceMainHandle) -> Self {
        let receiver = match role.retain_receiver_in_main() {
            Ok(receiver) => receiver,
            Err(raw) => panic!(
                "{}",
                role.failure_with_refusal("retain native context receiver", raw)
            ),
        };
        let mut scope = Self {
            role,
            context: None,
            receiver: Some(receiver),
            destruction_started: false,
        };
        scope.context = Some(
            match scope.role.with_ready(|ready| ready.context().clone()) {
                Ok(context) => context,
                Err(raw) => panic!(
                    "{}",
                    scope
                        .role
                        .failure_with_refusal("project native Context", raw)
                ),
            },
        );
        scope
    }"###,
                1,
            ),
            (
                r###"pub(in crate::packaged_qemu_executor::tests) fn into_retirement(
        mut self,
    ) -> Result<NativeServiceTerminal, NativeServiceReturnError> {
        self.destruction_started = true;
        drop(self.context.take());
        let acknowledgment = self
            .receiver
            .take()
            .and_then(|receiver| receiver.return_after_alias_destruction().err());
        let mut retirement = self.role.clone().into_retirement();
        if acknowledgment.is_some() {
            return Err(NativeServiceReturnError::Pending(
                NativeServiceReturnRefusal {
                    retirement,
                    acknowledgment,
                    retry: None,
                },
            ));
        }
        let retry = retirement.retry().err();
        match retirement.finish() {
            Ok(body) => {
                let failed = retry.is_some() || body.first_failure().is_some();
                let terminal = NativeServiceTerminal { body, retry };
                if failed {
                    Err(NativeServiceReturnError::Terminal(terminal))
                } else {
                    Ok(terminal)
                }
            }
            Err(retirement) => Err(NativeServiceReturnError::Pending(
                NativeServiceReturnRefusal {
                    retirement,
                    acknowledgment: None,
                    retry,
                },
            )),
        }
    }"###,
                1,
            ),
            (
                r###"impl Drop for NativeServiceScope {
    fn drop(&mut self) {
        if self.destruction_started {
            return;
        }
        self.role.prepared_selector().request_retirement();
        self.destruction_started = true;
        drop(self.context.take());
        if let Some(receiver) = self.receiver.take() {
            // The actual Main token journals alias destruction before its
            // fallible observation; refusal cannot free the native World.
            let _observation = receiver.return_after_alias_destruction();
        }
    }
}
"###,
                1,
            ),
            (
                r###"struct NativeServiceScope { role: ServiceMainHandle, context: Option<AttemptExecutionContext>, receiver: Option<ServiceMainReceiverHandle>, destruction_started: bool, }"###,
                1,
            ),
            (
                r###"struct NativeServiceReturnRefusal { retirement: PreparedSourceRetirement, acknowledgment: Option<ServiceMainPreclaimError>, retry: Option<PreparedSourceRefusal>, }"###,
                1,
            ),
            (
                r###"struct NativeServiceTerminal { body: crate::ProductionVmConstructionPostBody, retry: Option<PreparedSourceRefusal>, }"###,
                1,
            ),
        ],
        expressions: &[
            ("self.role.retry_prepared_body()", 1),
            ("retirement.retry()", 1),
        ],
        identifiers: &[("retry_prepared_body", 1), ("retry", 10)],
        companions: super::SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_campaign_lifecycle/campaign_run/executor/admitted",
        required: &[
            (
                r###"if let Err(first) = receiver.return_after_alias_destruction() {
            let returned =
                service.failure_with_refusal("return completed reproduction aliases", first);
            match &mut reproduced {
                Err(error) => error.receiver_return = Some(returned),
                Ok(_) => {
                    reproduced = Err(SynchronousCampaignExecutorCause::Prepared(returned).into())
                }
            }
        }
        let observation = match reproduced {
            Ok(observation) => observation,
            Err(error) => {
                let _retained = service.failure("retire failed completed reproduction");
                return Err(error);
            }
        };
        let mut retirement = service
            .prepared_selector()
            .service_main_handle()
            .into_retirement();"###,
                1,
            ),
            (
                r###"match retirement.finish() {
            Ok(terminal) if terminal.first_failure().is_some() => {
                return Err(
                    SynchronousCampaignExecutorCause::Terminal(std::sync::Mutex::new(terminal))
                        .into(),
                );
            }
            Ok(terminal) => drop(terminal),
            Err(_retirement) => {
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure("completed reproduction terminal disposal pending"),
                )
                .into());
            }
        }"###,
                1,
            ),
        ],
        expressions: &[("retirement.retry()", 1)],
        identifiers: &[("retry", 1)],
        companions: super::SHARED,
    },
];
