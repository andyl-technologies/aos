//! Native process evidence for branch-private hot-fork resources.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct ChildResources {
    pid: u32,
    command: Vec<String>,
    shmem: (u64, u64),
    wake_eventfd_id: u64,
    socket_inodes: BTreeSet<u64>,
    temporary_files: BTreeSet<(u64, u64)>,
    root_overlay: (u64, u64),
}

pub(super) fn assert_live_children_are_physically_private(
    cgroup_root: &Path,
    storage_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pids = BTreeSet::new();
    collect_cgroup_processes(cgroup_root, &mut pids)?;
    if pids.len() != 2 {
        return Err(format!(
            "target cgroups contain {} QEMU processes, expected two",
            pids.len()
        )
        .into());
    }
    let children = pids
        .into_iter()
        .map(|pid| inspect_child(pid, storage_root))
        .collect::<Result<Vec<_>, _>>()?;
    let [first, second] = children.as_slice() else {
        return Err("target process collection changed during inspection".into());
    };

    if first.shmem == second.shmem {
        return Err("live children share one setup-region memfd".into());
    }
    if first.wake_eventfd_id == second.wake_eventfd_id {
        return Err("live children share one plugin wake eventfd".into());
    }
    if first.root_overlay == second.root_overlay {
        return Err("live children share one writable qcow2 root".into());
    }
    if !first.socket_inodes.is_disjoint(&second.socket_inodes) {
        return Err("live children share a serial/control/export socket inode".into());
    }
    if !first.temporary_files.is_disjoint(&second.temporary_files) {
        return Err("live children share one temporary file".into());
    }

    for child in &children {
        assert_private_device_arguments(child)?;
    }

    eprintln!(
        "atomic-world phase=resource-isolation pids={},{} memfd={:?},{:?} wake-eventfd={},{} root={:?},{:?}",
        first.pid,
        second.pid,
        first.shmem,
        second.shmem,
        first.wake_eventfd_id,
        second.wake_eventfd_id,
        first.root_overlay,
        second.root_overlay,
    );
    Ok(())
}

pub(super) fn assert_live_sibling_lanes_are_physically_private(
    cgroup_root: &Path,
    storage_root: &Path,
    lanes: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut children = Vec::with_capacity(lanes.len());
    for lane in lanes {
        let mut processes = BTreeSet::new();
        collect_cgroup_processes(&cgroup_root.join(lane), &mut processes)?;
        let process_list = processes.into_iter().collect::<Vec<_>>();
        let [pid] = process_list.as_slice() else {
            return Err(format!("sibling lane {lane} must own exactly one QEMU process").into());
        };
        let child = inspect_child(*pid, &storage_root.join(lane))?;
        assert_private_device_arguments(&child)?;
        children.push(child);
    }

    for (index, first) in children.iter().enumerate() {
        for second in &children[index + 1..] {
            if first.pid == second.pid
                || first.shmem == second.shmem
                || first.wake_eventfd_id == second.wake_eventfd_id
                || first.root_overlay == second.root_overlay
                || !first.socket_inodes.is_disjoint(&second.socket_inodes)
                || !first.temporary_files.is_disjoint(&second.temporary_files)
            {
                return Err(format!(
                    "live siblings {} and {} share a process or writable resource",
                    first.pid, second.pid
                )
                .into());
            }
        }
    }
    Ok(())
}

fn collect_cgroup_processes(
    directory: &Path,
    pids: &mut BTreeSet<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        collect_cgroup_processes(&entry.path(), pids)?;
    }
    let processes = directory.join("cgroup.procs");
    if processes.exists() {
        for line in fs::read_to_string(processes)?.lines() {
            let pid = line.parse::<u32>()?;
            pids.insert(pid);
        }
    }
    Ok(())
}

fn inspect_child(
    pid: u32,
    storage_root: &Path,
) -> Result<ChildResources, Box<dyn std::error::Error>> {
    let process_root = PathBuf::from(format!("/proc/{pid}"));
    let command = fs::read(process_root.join("cmdline"))?
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8(argument.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    if command
        .first()
        .is_none_or(|binary| !binary.ends_with("qemu-system-x86_64"))
    {
        return Err(format!("target cgroup process {pid} is not QEMU").into());
    }
    let plugin_argument = command
        .windows(2)
        .find_map(|pair| (pair[0] == "-plugin").then_some(pair[1].as_str()))
        .ok_or("QEMU child omitted its plugin argument")?;
    let shmem_fd = plugin_fd(plugin_argument, "shmemfd")?;
    let wake_fd = plugin_fd(plugin_argument, "wakefd")?;
    let shmem = descriptor_identity(&process_root.join("fd").join(shmem_fd.to_string()))?;
    let shmem_target = fs::read_link(process_root.join("fd").join(shmem_fd.to_string()))?;
    if !shmem_target
        .to_string_lossy()
        .contains("memfd:crucible-qemu-shmem")
    {
        return Err(format!("QEMU child {pid} plugin shmemfd is not the setup memfd").into());
    }
    let wake_eventfd_id = eventfd_id(&process_root.join("fdinfo").join(wake_fd.to_string()))?;

    let mut socket_inodes = BTreeSet::new();
    let mut temporary_files = BTreeSet::new();
    let mut root_overlay = None;
    for entry in fs::read_dir(process_root.join("fd"))? {
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let rendered = target.to_string_lossy();
        if let Some(inode) = rendered
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
        {
            socket_inodes.insert(inode.parse::<u64>()?);
        }
        if target.starts_with("/tmp") {
            let identity = descriptor_identity(&entry.path())?;
            temporary_files.insert(identity);
        }
        if target.starts_with(storage_root)
            && target
                .file_name()
                .is_some_and(|name| name == crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME)
        {
            let identity = descriptor_identity(&entry.path())?;
            if root_overlay.replace(identity).is_some() {
                return Err(format!("QEMU child {pid} opened multiple root overlays").into());
            }
        }
    }
    if socket_inodes.len() < 3 {
        return Err(format!("QEMU child {pid} retained fewer than three private sockets").into());
    }
    let root_overlay = root_overlay.ok_or("QEMU child omitted its writable root overlay")?;

    Ok(ChildResources {
        pid,
        command,
        shmem,
        wake_eventfd_id,
        socket_inodes,
        temporary_files,
        root_overlay,
    })
}

fn assert_private_device_arguments(
    child: &ChildResources,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_network = child.command.iter().any(|argument| {
        argument.contains("virtio-net-pci") && argument.contains("crucible-net-device0")
    });
    let has_ninep = child.command.iter().any(|argument| {
        argument.contains("virtio-9p-pci") && argument.contains("crucible-9p-device0")
    });
    let has_private_serial = child.command.iter().any(|argument| {
        argument.contains("socket,id=crucible-console") && argument.contains("server=on")
    });
    if !has_network || !has_ninep || !has_private_serial {
        return Err(format!(
            "live child {} omitted the network, 9p, or private serial device",
            child.pid
        )
        .into());
    }
    if child
        .command
        .iter()
        .any(|argument| argument == "-pidfile" || argument.starts_with("-pidfile="))
    {
        return Err(format!("live child {} retained an ambient pidfile", child.pid).into());
    }
    if child.command.iter().any(|argument| {
        argument.contains("vhost-user")
            || argument.contains("virtfs-proxy-helper")
            || argument.contains("export-socket")
    }) {
        return Err(format!(
            "live child {} retained an ambient network or 9p export socket",
            child.pid
        )
        .into());
    }

    Ok(())
}

fn plugin_fd(plugin_argument: &str, name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    plugin_argument
        .split(',')
        .find_map(|field| {
            field
                .strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
        })
        .ok_or_else(|| format!("plugin argument omitted {name}").into())
        .and_then(|value| value.parse::<u32>().map_err(Into::into))
}

fn descriptor_identity(path: &Path) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn eventfd_id(path: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .find_map(|line| line.strip_prefix("eventfd-id:"))
        .ok_or_else(|| format!("{} omitted eventfd-id", path.display()).into())
        .and_then(|value| value.trim().parse::<u64>().map_err(Into::into))
}
