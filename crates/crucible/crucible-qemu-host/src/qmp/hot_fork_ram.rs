//! Checked child RAM resource-plan imports and exact custody acknowledgements.
//!
//! ```text
//! {"execute":"crucible-hot-fork-child-ram","arguments":{
//!   "action":"stage","plan-fdname":"plan","control-fdname":"control",
//!   "spill-fdname":"spill","template-generation":1,
//!   "process-contract-generation":2}}
//! ```

use super::*;

const QMP_HOT_FORK_CHILD_RAM_SCHEMA_VERSION: u32 = 1;

pub(crate) struct QmpHotForkChildRamDescriptors<'a> {
    pub(crate) plan: BorrowedFd<'a>,
    pub(crate) control: BorrowedFd<'a>,
    pub(crate) source: Option<BorrowedFd<'a>>,
    pub(crate) spill: BorrowedFd<'a>,
}

impl<S: QmpTimeoutStream> QemuQmpVmStateControlChannel<S> {
    pub(crate) fn install_hot_fork_child_ram(
        &mut self,
        names: &QmpHotForkChildRamNames,
        descriptors: QmpHotForkChildRamDescriptors<'_>,
        template: u64,
        contract: u64,
    ) -> Result<QmpHotForkChildRamState, QemuNodeChannelError> {
        names
            .validate_binding(template, contract)
            .map_err(QemuNodeChannelError::from)?;
        if names.source.is_some() != descriptors.source.is_some() {
            return Err(QemuNodeChannelError::new(
                "install child RAM source",
                "source roster mismatch",
            ));
        }

        for (name, descriptor) in [
            (&names.plan, descriptors.plan),
            (&names.control, descriptors.control),
            (&names.spill, descriptors.spill),
        ] {
            self.client
                .install_descriptor(name, descriptor)
                .map_err(QemuNodeChannelError::from)?;
        }
        match (&names.source, descriptors.source) {
            (Some(name), Some(descriptor)) => {
                self.client
                    .install_descriptor(name, descriptor)
                    .map_err(QemuNodeChannelError::from)?;
            }
            (None, None) => {}
            _ => {
                return Err(QemuNodeChannelError::new(
                    "install child RAM source",
                    "source roster mismatch",
                ));
            }
        }
        self.stage_hot_fork_child_ram(names, template, contract)
    }

    pub(crate) fn close_hot_fork_child_ram(
        &mut self,
        names: &QmpHotForkChildRamNames,
        generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.release_hot_fork_child_ram(generation)?;
        for name in [&names.plan, &names.control, &names.spill]
            .into_iter()
            .chain(names.source.iter())
        {
            self.client
                .close_descriptor(name)
                .map_err(QemuNodeChannelError::from)?;
        }
        Ok(())
    }
}

impl QmpHotForkChildRamNames {
    fn validate_binding(&self, template: u64, contract: u64) -> Result<(), QmpError> {
        let descriptors = [&self.plan, &self.control, &self.spill];
        if template == 0
            || contract == 0
            || descriptors.iter().enumerate().any(|(index, name)| {
                descriptors[index + 1..].contains(name) || self.source.as_ref() == Some(*name)
            })
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildRam,
                response: "invalid child RAM stage binding".into(),
            });
        }
        Ok(())
    }
}

pub(crate) const COMMAND: &str = "crucible-hot-fork-child-ram";

/// Names the separately imported, independently owned child resources.
#[derive(Clone, Debug)]
pub(crate) struct QmpHotForkChildRamNames {
    pub(crate) plan: QmpDescriptorName,
    pub(crate) control: QmpDescriptorName,
    pub(crate) source: Option<QmpDescriptorName>,
    pub(crate) spill: QmpDescriptorName,
}

/// Binds native stage custody to one source and child containment transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QmpHotForkChildRamState {
    pub(crate) generation: u64,
    pub(crate) template_generation: u64,
    pub(crate) process_contract_generation: u64,
    pub(crate) staged: bool,
    pub(crate) consumed: bool,
    pub(crate) source_bound: bool,
}

pub(super) enum Request<'a> {
    Stage {
        names: &'a QmpHotForkChildRamNames,
        template: u64,
        contract: u64,
    },
    Query,
    Release(u64),
}

impl Request<'_> {
    pub(super) fn wire_value(&self) -> Value {
        match self {
            Self::Stage {
                names,
                template,
                contract,
            } => {
                let mut fields = json!({"action":"stage","plan-fdname":names.plan.as_str(),
                    "control-fdname":names.control.as_str(),"spill-fdname":names.spill.as_str(),
                    "template-generation":template,"process-contract-generation":contract});
                if let Some(source) = &names.source {
                    fields["source-fdname"] = json!(source.as_str());
                }
                fields
            }
            Self::Query => json!({"action":"query"}),
            Self::Release(generation) => json!({"action":"release","generation":generation}),
        }
    }
}

fn malformed(value: &Value) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildRam,
        response: value.to_string(),
    }
}

pub(super) fn parse(value: &Value) -> Result<QmpHotForkChildRamState, QmpError> {
    let object = value.as_object().ok_or_else(|| malformed(value))?;
    if object.len() != 7
        || object.get("schema-version").and_then(Value::as_u64)
            != Some(u64::from(QMP_HOT_FORK_CHILD_RAM_SCHEMA_VERSION))
    {
        return Err(malformed(value));
    }
    let number = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(value))
    };
    let flag = |field| {
        object
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(|| malformed(value))
    };
    let state = QmpHotForkChildRamState {
        generation: number("generation")?,
        template_generation: number("template-generation")?,
        process_contract_generation: number("process-contract-generation")?,
        staged: flag("staged")?,
        consumed: flag("consumed")?,
        source_bound: flag("source-bound")?,
    };
    let valid = if state.staged {
        state.generation != 0
            && state.template_generation != 0
            && state.process_contract_generation != 0
    } else {
        state.generation == 0
            && state.template_generation == 0
            && state.process_contract_generation == 0
            && !state.consumed
            && !state.source_bound
    };
    if !valid {
        return Err(malformed(value));
    }
    Ok(state)
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(crate) fn stage_hot_fork_child_ram(
        &mut self,
        names: &QmpHotForkChildRamNames,
        template: u64,
        contract: u64,
    ) -> Result<QmpHotForkChildRamState, QmpError> {
        names.validate_binding(template, contract)?;
        let state = self.child_ram_request(Request::Stage {
            names,
            template,
            contract,
        })?;
        if !state.staged
            || state.consumed
            || state.template_generation != template
            || state.process_contract_generation != contract
            || state.source_bound != names.source.is_some()
        {
            self.poisoned = true;
            self.stream.get_mut().poison_qmp_stream();
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildRam,
                response: format!("mismatched child RAM stage: {state:?}"),
            });
        }
        Ok(state)
    }

    pub(crate) fn query_hot_fork_child_ram(&mut self) -> Result<QmpHotForkChildRamState, QmpError> {
        self.child_ram_request(Request::Query)
    }

    pub(crate) fn release_hot_fork_child_ram(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildRamState, QmpError> {
        if generation == 0 {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildRam,
                response: "zero child RAM release generation".into(),
            });
        }
        let state = self.child_ram_request(Request::Release(generation))?;
        if state.staged {
            return Err(malformed(&json!({"generation":state.generation})));
        }
        Ok(state)
    }

    fn child_ram_request(
        &mut self,
        request: Request<'_>,
    ) -> Result<QmpHotForkChildRamState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildRam { request })?;
        let result = parse(&response.value);
        if result.is_err() {
            self.poisoned = true;
            self.stream.get_mut().poison_qmp_stream();
        }
        result
    }
}

#[cfg(test)]
mod tests;
