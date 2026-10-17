//! Child RAM descriptor validation and independent monitor-name retirement.

use std::error::Error;
use std::io::Cursor;
use std::os::fd::AsFd;

use super::*;

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for ScriptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn channel(responses: &[Value]) -> Result<QemuQmpVmStateControlChannel<ScriptedStream>, QmpError> {
    let mut input = Vec::new();
    for response in [
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ]
    .iter()
    .chain(responses)
    {
        input.extend_from_slice(response.to_string().as_bytes());
        input.push(b'\n');
    }
    QmpClient::connect(ScriptedStream {
        input: Cursor::new(input),
        written: Vec::new(),
    })
    .map(QemuQmpVmStateControlChannel::new)
}

fn names() -> Result<QmpHotForkChildRamNames, QmpError> {
    Ok(QmpHotForkChildRamNames {
        plan: QmpDescriptorName::new("child-plan")?,
        control: QmpDescriptorName::new("child-control")?,
        source: Some(QmpDescriptorName::new("child-source")?),
        spill: QmpDescriptorName::new("child-spill")?,
    })
}

fn commands(
    channel: &QemuQmpVmStateControlChannel<ScriptedStream>,
) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(&channel.client.stream.get_ref().written)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

fn released() -> Value {
    json!({"return":{"schema-version":1,"generation":0,"template-generation":0,
        "process-contract-generation":0,"staged":false,"consumed":false,"source-bound":false}})
}

#[test]
fn invalid_child_roster_refuses_before_any_descriptor_import() -> Result<(), Box<dyn Error>> {
    let file = std::fs::File::open("/dev/null")?;
    let valid = names()?;
    let mut duplicate = valid.clone();
    duplicate.control = duplicate.plan.clone();
    for (names, template, source) in [
        (valid.clone(), 1, None),
        (duplicate, 1, Some(file.as_fd())),
        (valid, 0, Some(file.as_fd())),
    ] {
        let mut channel = channel(&[])?;
        assert!(
            channel
                .install_hot_fork_child_ram(
                    &names,
                    QmpHotForkChildRamDescriptors {
                        plan: file.as_fd(),
                        control: file.as_fd(),
                        source,
                        spill: file.as_fd(),
                    },
                    template,
                    1,
                )
                .is_err()
        );
        assert_eq!(commands(&channel)?.len(), 1);
    }
    Ok(())
}

#[test]
fn native_release_precedes_every_independent_monitor_name_close() -> Result<(), Box<dyn Error>> {
    let mut channel = channel(&[
        released(),
        json!({"return":{}}),
        json!({"return":{}}),
        json!({"return":{}}),
        json!({"return":{}}),
    ])?;
    let names = names()?;
    channel.close_hot_fork_child_ram(&names, 7)?;

    let commands = commands(&channel)?;
    assert_eq!(commands.len(), 6);
    assert_eq!(commands[1]["execute"], COMMAND);
    assert_eq!(commands[1]["arguments"]["action"], "release");
    assert_eq!(commands[1]["arguments"]["generation"], 7);
    for (command, name) in commands[2..].iter().zip([
        &names.plan,
        &names.control,
        &names.spill,
        names.source.as_ref().ok_or("source name absent")?,
    ]) {
        assert_eq!(command["exec-oob"], "closefd");
        assert_eq!(command["arguments"]["fdname"], name.as_str());
    }
    Ok(())
}

#[test]
fn a_refused_monitor_close_cannot_report_complete_custody_release() -> Result<(), Box<dyn Error>> {
    let mut channel = channel(&[
        released(),
        json!({"return":{}}),
        json!({"error":{"class":"GenericError","desc":"close refused"}}),
    ])?;
    assert!(channel.close_hot_fork_child_ram(&names()?, 7).is_err());
    let commands = commands(&channel)?;
    assert_eq!(commands.len(), 4);
    assert_eq!(commands[3]["arguments"]["fdname"], "child-control");
    Ok(())
}
