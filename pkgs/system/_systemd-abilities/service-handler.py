"""Native rich service rendering and retained configuration reconciliation.

The process consumes the native activation Invocation directly. Build callers
use ``render`` with the same merged service inputs to materialize bootstrap
units without changing the live machine.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


from aos_configuration import (
    ConfigurationHandler, absolute, checked_text, configuration_bytes, digest,
    durable_unlink, durable_write, locked_dispatch, mode, read_digest,
    read_invocation, serialize_toml, synchronize_directory,
)


TRUE_EXECUTABLE = None
FLOCK_EXECUTABLE = None
MAC_CONDITION_EXECUTABLE = None


CAPABILITIES = {
    "adjust-host-clock": "CAP_SYS_TIME",
    "administer-host": "CAP_SYS_ADMIN",
    "administer-network": "CAP_NET_ADMIN",
    "administer-resource-limits": "CAP_SYS_RESOURCE",
    "bind-privileged-network-port": "CAP_NET_BIND_SERVICE",
    "bypass-file-access": "CAP_DAC_OVERRIDE",
    "bypass-file-read-search": "CAP_DAC_READ_SEARCH",
    "change-file-ownership": "CAP_CHOWN",
    "change-group-identity": "CAP_SETGID",
    "change-root-directory": "CAP_SYS_CHROOT",
    "change-user-identity": "CAP_SETUID",
    "create-device-node": "CAP_MKNOD",
    "inspect-processes": "CAP_SYS_PTRACE",
    "raw-network": "CAP_NET_RAW",
}


OPERATIONS = {
    "change-file-ownership": "@chown", "change-process-identity": "@setuid",
    "clock": "@clock", "cpu-emulation": "@cpu-emulation", "debug": "@debug",
    "keyring": "@keyring", "module": "@module", "mount": "@mount",
    "obsolete": "@obsolete", "privileged": "@privileged", "raw-io": "@raw-io",
    "reboot": "@reboot", "resource-control": "@resources",
    "set-process-privileges": "capset", "swap": "@swap",
}


OPERATION_PROFILES = {
    "privileged": None,
    "restricted": "@system-service",
    "system-service": "@system-service",
}


def quote(value, expand_environment=False):
    value = checked_text(value)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace(
        "\n", "\\n").replace("\r", "\\r").replace("%", "%%")
    if expand_environment:
        escaped = escaped.replace("$", "$$")
    return '"' + escaped + '"'


def token(value):
    value = checked_text(value)
    if not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+", value):
        raise ValueError("invalid service manager token")
    return value


def socket_address(value):
    value = checked_text(value)
    if "\n" in value or "\r" in value or value != value.strip() or value.endswith("\\"):
        raise ValueError("socket address cannot require scalar whitespace or continuation escaping")
    # Listen*= resolves specifiers directly; it does not remove Exec*= quoting.
    return value.replace("%", "%%")


def yes(value):
    return "yes" if value else "no"


def milliseconds(value):
    if not isinstance(value, int) or value < 0:
        raise ValueError("invalid duration")
    return str(value) + "ms"


def command(value):
    executable = value["executable"]
    arguments = [absolute(executable["path"])] + executable["arguments"]
    encoded = (quote(argument, expand_environment=True) for argument in arguments)
    return ("-" if value["ignore_failure"] else "") + " ".join(encoded)


def unit_ref(value):
    value = checked_text(value)
    if value.startswith(("/", "configuration:")) or "#" in value:
        return None
    if value.endswith((".target", ".service", ".socket", ".mount", ".swap", ".timer", ".path")):
        return token(value)
    return token(value) + ".service"


class Unit:
    """Stores directives in section order and escapes values at their boundary."""

    def __init__(self):
        self.sections = {"Unit": [], "Service": [], "Install": []}

    def add(self, key, value, section="Service"):
        if value is not None:
            value = str(value)
            if "\n" in value or "\r" in value or "\0" in value:
                raise ValueError("unescaped control character in manager directive")
            self.sections.setdefault(section, []).append(f"{key}={value}")

    def repeat(self, key, values, section="Service", encode=str):
        for value in values:
            self.add(key, encode(value), section)

    def text(self):
        return "\n\n".join(
            "[" + section + "]\n" + "\n".join(values)
            for section, values in self.sections.items() if values
        ) + "\n"


def service_identity(value):
    identity = value.get("manager_identity") or {}
    name = token(identity.get("name") or value.get("service") or value["instance"])
    selection = value.get("instantiation") or {"kind": "singleton"}
    if selection["kind"] == "template":
        return token(selection["template"]) + "@.service"
    if selection["kind"] == "instance":
        template = unit_ref(selection["template_resource"])
        if "@.service" not in template:
            raise ValueError("service instance requires a template resource")
        instance = selection["instance"].encode()
        escaped = "".join(chr(byte) if chr(byte).isalnum() and byte < 128 else f"\\x{byte:02x}" for byte in instance)
        return template.replace("@.service", "@" + escaped + ".service")
    return name + ".service"


def hardening(unit, value):
    policy = (value.get("policy") or {}).get("hardening")
    if not policy:
        return
    bounds = policy["privilege_bounds"]
    if bounds["kind"] != "unrestricted":
        if not set(policy["ambient_privileges"]).issubset(bounds["privileges"]):
            raise ValueError("ambient privileges exceed bounds")
        unit.add("CapabilityBoundingSet", " ".join(CAPABILITIES[p] for p in bounds["privileges"]))
    if set(policy["operation_allow"]) & set(policy["operation_deny"]):
        raise ValueError("operation allow and deny sets overlap")
    unit.add("AmbientCapabilities", " ".join(CAPABILITIES[p] for p in policy["ambient_privileges"]))
    unit.add("Delegate", yes(policy["resource_control_delegation"]))
    unit.add("ProtectControlGroups", {"host": "no", "read-only": "yes", "private": "strict"}[policy["resource_control_access"]])
    unit.add("PrivateDevices", yes(policy["device_access_scope"] == "private"))
    for field, directive in {
        "host_clock_mutation": "ProtectClock", "host_name_mutation": "ProtectHostname",
        "operating_system_log_access": "ProtectKernelLogs",
        "operating_system_extension_access": "ProtectKernelModules",
        "operating_system_tunable_access": "ProtectKernelTunables",
        "writable_executable_memory": "MemoryDenyWriteExecute",
        "permit_realtime": "RestrictRealtime", "permit_elevated_file_identity": "RestrictSUIDSGID",
    }.items():
        unit.add(directive, yes(not policy[field]))
    unit.add("LockPersonality", yes(policy["lock_execution_personality"]))
    unit.add("RemoveIPC", yes(policy.get("remove_interprocess_communication", False)))
    domains = policy["isolation_domains"]
    for domain, directive in {"ipc": "PrivateIPC", "filesystem": "PrivateMounts", "network": "PrivateNetwork", "process": "PrivatePIDs"}.items():
        if domain in domains:
            unit.add(directive, "yes")
    if "identity" in domains:
        unit.add("PrivateUsers", {"full": "full", "identity": "identity", "none": "no", "self": "self"}[policy["isolated_identity_mapping"]])
    families = {"ipv4": "AF_INET", "ipv6": "AF_INET6", "local": "AF_UNIX", "raw-packet": "AF_PACKET", "route-control": "AF_NETLINK"}
    if policy["network_families"]:
        unit.add("RestrictAddressFamilies", " ".join(families[f] for f in policy["network_families"]))
    unit.add("RestrictNamespaces", yes(policy["isolation_domain_creation"] == "denied"))
    unit.add("OOMScoreAdjust", policy["memory_pressure_adjustment"])
    unit.add("ProtectProc", {"all": "default", "same-user": "ptraceable", "self": "invisible"}[policy["process_visibility"]])
    unit.add("SELinuxContext", policy.get("security_label"))
    unit.add("SystemCallArchitectures", " ".join(map(token, policy["operation_architectures"])))
    allow = [OPERATIONS[o] for o in policy["operation_allow"]]
    deny = [OPERATIONS[o] for o in policy["operation_deny"]]
    # Profiles describe workloads; @privileged is a narrow syscall group,
    # not an unrestricted workload. Explicit exceptions follow exclusions.
    unit.add("SystemCallFilter", OPERATION_PROFILES[policy["operation_profile"]])
    unit.add("SystemCallFilter", "~" + " ".join(deny) if deny else None)
    unit.add("SystemCallFilter", " ".join(allow) if allow else None)
    if policy["denied_operation_action"] == "return-permission-denied":
        unit.add("SystemCallErrorNumber", "EPERM")


def process_features(unit, value):
    hardening_policy = (value.get("policy") or {}).get("hardening") or {}
    isolation = value.get("isolation") or {}
    deny_privilege_escalation = (
        hardening_policy.get("allow_privilege_escalation") is False
        or isolation.get("privilege") == "unprivileged"
    )
    unit.add("NoNewPrivileges", yes(deny_privilege_escalation))

    identity = value.get("identity")
    if identity:
        unit.add("User", token(identity["principal"]) if identity.get("principal") else None)
        unit.add("Group", token(identity["primary_group"]) if identity.get("primary_group") else None)
        unit.add("SupplementaryGroups", " ".join(map(token, identity["supplementary_groups"])))
        unit.add("DynamicUser", yes(identity["ephemeral"]))
        unit.add("UMask", identity["file_creation_mask"])
    environment = value.get("environment")
    if environment:
        unit.repeat("Environment", [f"{token(k)}={v}" for k, v in environment["variables"].items()], encode=quote)
        search_path = [
            absolute(path) + suffix
            for path in environment["search_path"]
            for suffix in ("/bin", "/sbin")
        ]
        unit.add("ExecSearchPath", ":".join(search_path))
    resources = value.get("resources") or {}
    unit.add("Slice", token(resources["resource_group"]) + ".slice" if resources.get("resource_group") else None)
    for field, directive in {"open_files": "LimitNOFILE", "processes": "LimitNPROC", "tasks": "TasksMax", "locked_memory_bytes": "LimitMEMLOCK", "memory_high_bytes": "MemoryHigh", "memory_max_bytes": "MemoryMax", "memory_swap_max_bytes": "MemorySwapMax"}.items():
        limit = resources.get(field)
        if limit:
            unit.add(directive, "infinity" if limit["kind"] == "unbounded" else limit["value"])
    unit.add("OOMPolicy", resources.get("oom_policy"))
    scheduling = value.get("scheduling")
    if scheduling:
        unit.add("CPUSchedulingPolicy", scheduling.get("cpu_policy"))
        unit.add("Nice", scheduling["nice"])
        unit.add("IOSchedulingClass", scheduling["io_class"])
        unit.add("IOSchedulingPriority", scheduling["io_priority"])
    logging = value.get("logging")
    if logging:
        targets = {"console": "console", "discard": "null", "inherit": "inherit", "structured": "journal", "structured-and-console": "journal+console"}
        unit.add("StandardOutput", targets[logging["standard_output"]])
        unit.add("StandardError", targets[logging["standard_error"]])
        unit.add("LogNamespace", logging.get("namespace"))
        unit.repeat("LogsDirectory", logging["directories"], encode=quote)
        unit.add("LogsDirectoryMode", logging["directory_mode"])
    for entry in (value.get("configuration") or {}).get("views", []):
        unit.add("ReadOnlyPaths", ("-" if entry["optional"] else "") + quote(absolute(entry["source"])))
    for entry in (value.get("storage") or {}).get("mounts", []):
        path = absolute(entry["source"])
        if entry.get("ownership", "provider") == "service-identity":
            prefixes = {"/run/": "RuntimeDirectory", "/var/lib/": "StateDirectory", "/var/cache/": "CacheDirectory", "/var/log/": "LogsDirectory"}
            selected = [(prefix, key) for prefix, key in prefixes.items() if path.startswith(prefix)]
            if len(selected) != 1:
                raise ValueError("service-owned storage requires a standard managed directory")
            prefix, key = selected[0]
            unit.add(key, quote(path[len(prefix):]))
        else:
            unit.add("ReadOnlyPaths" if entry["access"] == "read-only" else "ReadWritePaths", quote(path))
    for entry in (value.get("credentials") or {}).get("views", []):
        key = "LoadCredentialEncrypted" if entry["encrypted"] else "LoadCredential"
        unit.add(key, quote(token(entry["name"]) + ":" + absolute(entry["reference"])))
        if entry.get("environment_variable"):
            unit.add("Environment", quote(token(entry["environment_variable"]) + "=%d/" + token(entry["name"])).replace("%%d", "%d"))
    isolation = value.get("isolation")
    if isolation:
        unit.add("PrivateNetwork", yes(isolation["network"] != "host"))
        if isolation["network"] == "none":
            unit.add("IPAddressDeny", "any")
        unit.add("PrivateTmp", {"shared": "no", "private": "yes", "disconnected": "disconnected"}[isolation["temporary_directory"]])
        unit.add("ProtectSystem", {"host": "no", "private": "strict", "read-only-system": "strict", "read-only-software": "full"}[isolation["filesystem"]])
        unit.add("ProtectHome", {"host": "no", "read-only": "read-only", "inaccessible": "yes"}[isolation["home_access"]])
        unit.add("ProtectProc", "invisible" if isolation["process_visibility"] == "private" else "default")
        unit.add("KillMode", {"all-processes": "control-group", "main-process": "process", "mixed": "mixed"}[isolation["termination_scope"]])
        unit.add("LimitCORE", "infinity" if isolation["permit_core_dumps"] else "0")
        for entry in isolation.get("temporary_filesystems", []):
            unit.add("TemporaryFileSystem", quote(absolute(entry["path"]) + (":ro" if entry["read_only"] else ":rw")))
        for entry in isolation["host_paths"]:
            unit.add("BindReadOnlyPaths" if entry["mode"] == "read-only" else "BindPaths", quote(absolute(entry["source"])))
        if isolation.get("root_directory"):
            unit.add("RootDirectory", quote(absolute(isolation["root_directory"])))
        if isolation["devices"]:
            unit.add("DevicePolicy", "closed")
        for entry in isolation["devices"]:
            access = ("r" if entry["read"] else "") + ("w" if entry["write"] else "") + ("m" if entry["create_node"] else "")
            unit.add("DeviceAllow", quote(absolute(entry["source"])) + " " + access)
    terminal = value.get("terminal")
    if terminal:
        unit.add("TTYPath", quote(absolute(terminal["device"])))
        for field, key in {"reset": "TTYReset", "hangup": "TTYVHangup", "deallocate": "TTYVTDisallocate", "send_hangup_on_stop": "SendSIGHUP"}.items():
            unit.add(key, yes(terminal[field]))
        unit.add("UtmpIdentifier", terminal.get("session_identifier"))
    hardening(unit, value)


def condition_features(unit, value):
    for condition in (value.get("conditions") or {}).get("all", []):
        prefix = "!" if condition["negated"] else ""
        if condition["kind"] == "path":
            keys = {"exists": "ConditionPathExists", "is-directory": "ConditionPathIsDirectory", "is-mount-point": "ConditionPathIsMountPoint", "is-nonempty": "ConditionDirectoryNotEmpty"}
            # Condition paths are scalar values; systemd does not unquote them.
            path = absolute(condition["path"]).replace("%", "%%")
            unit.add(keys[condition["predicate"]], prefix + path, "Unit")
        elif condition["kind"] == "kernel-argument":
            unit.add("ConditionKernelCommandLine", prefix + quote(condition["argument"]), "Unit")
        elif condition["kind"] == "mandatory-access-control":
            if condition["state"] == "available":
                unit.add("ConditionSecurity", prefix + "selinux", "Unit")
            else:
                if MAC_CONDITION_EXECUTABLE is None:
                    raise ValueError("enforcing MAC condition requires a pinned condition executable")
                arguments = ["check-mac"] + (["--negated"] if condition["negated"] else [])
                unit.add("ExecCondition", command({
                    "executable": {"path": MAC_CONDITION_EXECUTABLE, "arguments": arguments},
                    "ignore_failure": False,
                }))
        else:
            raise ValueError("unsupported service condition")
    for item in ((value.get("policy") or {}).get("runtimeConditions") or {}).get("privileges", []):
        unit.add("ConditionCapability", ("" if item["available"] else "!") + CAPABILITIES[item["privilege"]], "Unit")


def realize_service(value):
    lifecycle = value.get("lifecycle")
    if not lifecycle:
        raise ValueError("enabled service has no lifecycle")
    unit_name = service_identity(value)
    unit = Unit()
    unit.add("Description", quote(lifecycle["description"]), "Unit")
    dependencies = value.get("dependencies") or {}
    for field, key in {"after": "After", "before": "Before", "requires": "Requires", "wants": "Wants", "requisite": "Requisite", "conflicts": "Conflicts", "binds_to": "BindsTo", "part_of": "PartOf", "upholds": "Upholds"}.items():
        unit.repeat(key, filter(None, map(unit_ref, dependencies.get(field, []))), "Unit")
    unit.add("DefaultDependencies", yes(dependencies.get("implicit_dependencies", True)), "Unit")
    for path in dependencies.get("required_mounts", []):
        unit.add("RequiresMountsFor", quote(absolute(path)), "Unit")
    for binding in (value.get("activation") or {}).get("bindings", []):
        target = unit_ref(binding["resource"])
        if target:
            relationship = binding["relationship"]
            if relationship == "service-depends-on-resource":
                unit.add("Requires", target, "Unit")
                unit.add("After", target, "Unit")
            elif relationship == "service-member-of-resource":
                unit.add("PartOf", target, "Unit")
    condition_features(unit, value)
    supervision = value.get("supervision") or {}
    readiness = value.get("readiness") or {}
    service_type = {"foreground": "simple", "forking": "forking", "oneshot": "oneshot"}[lifecycle["execution_model"]]
    if readiness.get("mechanism") == "process-signal":
        if readiness["signal_scope"] == "none":
            raise ValueError("notification readiness requires a process signal scope")
        if supervision.get("startup_protocol") == "notification" and supervision["notification_access"] != readiness["signal_scope"]:
            raise ValueError("notification supervision and readiness scopes disagree")
        service_type = "notify"
    elif supervision.get("startup_protocol") == "notification":
        service_type = "notify"
    elif supervision.get("startup_protocol") == "bus-name":
        service_type = "dbus"
    if (value.get("terminal") or {}).get("start_when_idle"):
        service_type = "idle"
    unit.add("Type", service_type)
    unit.add("BusName", supervision.get("bus_name"))
    if readiness.get("mechanism") == "process-signal":
        unit.add("NotifyAccess", {"main-process": "main", "all-processes": "all"}[readiness["signal_scope"]])
    elif supervision.get("startup_protocol") == "notification":
        unit.add("NotifyAccess", {"none": "none", "main-process": "main", "all-processes": "all"}[supervision["notification_access"]])
    if lifecycle.get("working_directory"):
        unit.add("WorkingDirectory", quote(absolute(lifecycle["working_directory"])))
    for field, key in {"condition": "ExecCondition", "pre_start": "ExecStartPre", "start": "ExecStart", "post_start": "ExecStartPost", "stop": "ExecStop", "post_stop": "ExecStopPost"}.items():
        if field == "start" and value.get("concurrency"):
            if FLOCK_EXECUTABLE is None or len(lifecycle[field]) != 1 or lifecycle["execution_model"] == "forking":
                raise ValueError("exclusive concurrency requires one non-forking start command and a pinned flock executable")
            lock = "/run/aos-native-service-locks/" + digest(value["concurrency"]["group"].encode()) + ".lock"
            original = lifecycle[field][0]
            executable = original["executable"]
            arguments = ["--exclusive", "--nonblock", "--no-fork", lock, executable["path"], *executable["arguments"]]
            unit.add(key, command({"executable": {"path": FLOCK_EXECUTABLE, "arguments": arguments}, "ignore_failure": original["ignore_failure"]}))
        else:
            unit.repeat(key, lifecycle[field], encode=command)
    for entry in lifecycle["environment_files"]:
        unit.add("EnvironmentFile", ("-" if entry["optional"] else "") + quote(absolute(entry["source"])))
    unit.add("Restart", {"never": "no", "always": "always", "on-failure": "on-failure"}[lifecycle["restart"]])
    unit.add("RestartSec", milliseconds(lifecycle["restart_delay_millis"]))
    unit.add("RemainAfterExit", yes(lifecycle["remain_after_exit"] or readiness.get("mechanism") == "successful-exit"))
    unit.add("TimeoutStartSec", "infinity" if lifecycle.get("start_timeout_unbounded") else milliseconds(lifecycle["start_timeout_millis"]))
    unit.add("TimeoutStopSec", "infinity" if lifecycle.get("stop_timeout_unbounded") else milliseconds(lifecycle["stop_timeout_millis"]))
    reload = value.get("reload") or {}
    if reload.get("strategy") == "command":
        unit.repeat("ExecReload", reload["commands"], encode=command)
    elif reload.get("strategy") == "signal":
        unit.add("ReloadSignal", token(reload["signal"]))
    if reload.get("completion") == "notification":
        unit.add("Type", "notify-reload")
    termination = value.get("termination") or {}
    unit.add("KillSignal", termination.get("signal"))
    unit.add("FinalKillSignal", termination.get("final_signal"))
    unit.add("PIDFile", quote(absolute(termination["process_id_file"])) if termination.get("process_id_file") else None)
    if termination:
        unit.add("KillMode", "control-group" if termination["send_to_all_processes"] else "process")
    watchdog = value.get("watchdog")
    if watchdog:
        unit.add("WatchdogSec", milliseconds(watchdog["timeout_millis"]))
        unit.add("RestartPreventExitStatus" if watchdog["action"] == "stop" else "RestartForceExitStatus", "SIGABRT")
    start = value.get("start_policy") or {}
    unit.add("SuccessExitStatus", " ".join(map(str, start["accepted_exit_statuses"])) if start else None)
    unit.add("RestartPreventExitStatus", " ".join(map(str, start["restart_preventing_exit_statuses"])) if start else None)
    unit.add("StartLimitIntervalSec", milliseconds(start["rate_interval_millis"]) if start.get("rate_interval_millis") else None, "Unit")
    unit.add("StartLimitBurst", start.get("rate_burst"), "Unit")
    failure = value.get("failure_policy") or {}
    unit.repeat("OnFailure", filter(None, map(unit_ref, failure.get("handlers", []))), "Unit")
    if failure:
        unit.add("OnFailureJobMode", {"enqueue": "replace", "isolate-active-goal": "isolate", "replace-active-goal": "replace-irreversibly"}[failure["dispatch"]], "Unit")
    if value.get("concurrency"):
        unit.add("X-AOS-ConcurrencyGroup", token(value["concurrency"]["group"]), "Unit")
    process_features(unit, value)
    device_policy = (value.get("policy") or {}).get("devicePolicy")
    if device_policy:
        unit.add("DevicePolicy", "closed" if device_policy["baseline_access"] == "standard-runtime-devices" else "strict")
        classes = {"fuse": "fuse", "kernel-message": "kmsg", "network-tunnel": "tun", "precision-time": "ptp", "pulse-per-second": "pps", "real-time-clock": "rtc"}
        for rule in device_policy["rules"]:
            selector = rule["selector"]
            kind = "char" if selector["device_type"] == "character" else "block"
            name = classes[selector["class"]] if selector["kind"] == "class" else str(selector["major"]) + ":" + str(selector.get("minor") if selector.get("minor") is not None else "*")
            permissions = ("r" if rule["read"] else "") + ("w" if rule["write"] else "") + ("m" if rule["create"] else "")
            unit.add("DeviceAllow", f"{kind}-{name} {permissions}")
    rendered = {}
    for directory in (value.get("directories") or {}).get("managed", []):
        if TRUE_EXECUTABLE is None:
            raise ValueError("managed directories require a pinned no-op executable")
        path = directory["path"]
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("managed directory requires a relative path")
        directory_name = "aos-directory-" + hashlib.sha256((unit_name + ":" + directory["purpose"] + ":" + path).encode()).hexdigest()[:24] + ".service"
        directory_unit = Unit()
        directory_unit.add("Description", quote("Managed " + directory["purpose"] + " directory " + path), "Unit")
        directory_unit.add("Before", unit_name, "Unit")
        directory_unit.add("PartOf", unit_name, "Unit")
        directory_unit.add("Type", "oneshot")
        directory_unit.add("RemainAfterExit", "yes")
        directory_unit.add("ExecStart", quote(absolute(TRUE_EXECUTABLE)))
        kinds = {"runtime": "RuntimeDirectory", "state": "StateDirectory", "cache": "CacheDirectory", "logs": "LogsDirectory", "configuration": "ConfigurationDirectory"}
        directive = kinds[directory["purpose"]]
        directory_unit.add(directive, quote(path))
        directory_unit.add(directive + "Mode", directory["mode"])
        identity = value.get("identity") or {}
        directory_unit.add("User", directory.get("owner") or identity.get("principal"))
        directory_unit.add("Group", directory.get("group") or identity.get("primary_group"))
        if directory["purpose"] == "runtime":
            directory_unit.add("RuntimeDirectoryPreserve", {"service-lifetime": "no", "restart": "restart", "persistent": "yes"}[directory["retention"]])
        if directory["retention"] == "service-lifetime":
            directory_unit.add("BindsTo", unit_name, "Unit")
        rendered[directory_name] = directory_unit.text()
        unit.add("Requires", directory_name, "Unit")
        unit.add("After", directory_name, "Unit")
        # Splitting allocation into a helper must retain *Directory= namespace access.
        roots = {"runtime": "/run/", "state": "/var/lib/", "cache": "/var/cache/", "logs": "/var/log/", "configuration": "/etc/"}
        unit.add("BindPaths", quote(roots[directory["purpose"]] + path))
    rendered[unit_name] = unit.text()
    links = {}
    for field, relationship in {"wanted_by": "wants", "required_by": "requires"}.items():
        for reference in dependencies.get(field, []):
            target = unit_ref(reference)
            if target:
                links[f"{target}.{relationship}/{unit_name}"] = "../" + unit_name
    owner = value.get("activation_owner", value.get("activationOwner", "ability"))
    if value.get("enabled", value.get("enable", False)) and not links and owner == "manager":
        links[f"multi-user.target.wants/{unit_name}"] = "../" + unit_name
    for alias in (value.get("manager_identity") or {}).get("aliases", []):
        links[token(alias) + ".service"] = unit_name
    sockets = (value.get("socket_activation") or {}).get("sockets", [])
    socket_names = {s["name"]: token(s.get("manager_name") or value["service"] + "-" + s["name"]) + ".socket" for s in sockets}
    socket_dependencies = (value.get("socket_activation") or {}).get("service_dependencies", {})
    for field, key in {"after": "After", "binds_to": "BindsTo", "requires": "Requires", "wants": "Wants"}.items():
        for name in socket_dependencies.get(field, []):
            unit.add(key, socket_names[name], "Unit")
    rendered[unit_name] = unit.text()
    starts = []
    for socket in sockets:
        name = socket_names[socket["name"]]
        document = Unit()
        document.add("Description", quote(lifecycle["description"] + " (" + socket["name"] + ")"), "Unit")
        document.add("Service", unit_name, "Socket")
        document.add("SocketMode", socket["mode"], "Socket")
        document.add("DirectoryMode", socket.get("directory_mode", "0755"), "Socket")
        for prerequisite in socket.get("prerequisites", []):
            document.add("After", unit_ref(prerequisite), "Unit")
            document.add("Requires", unit_ref(prerequisite), "Unit")
        document.add("SocketUser", socket.get("owner"), "Socket")
        document.add("SocketGroup", socket.get("group"), "Socket")
        document.add("RemoveOnStop", yes(socket["remove_on_stop"]), "Socket")
        for endpoint in socket["endpoints"]:
            if endpoint["kind"] == "unix":
                document.add("ListenStream", socket_address(absolute(endpoint["path"])), "Socket")
            else:
                address = checked_text(endpoint["address"])
                if ":" in address and not address.startswith("["):
                    address = "[" + address + "]"
                document.add("ListenStream" if endpoint["transport"] == "tcp" else "ListenDatagram", socket_address(address + ":" + str(endpoint["port"])), "Socket")
        for field, key in {"after": "After", "binds_to": "BindsTo"}.items():
            document.repeat(key, (socket_names[n] for n in socket.get(field, [])), "Unit")
        rendered[name] = document.text()
        if socket["enabled"] and value.get("enabled", value.get("enable", False)):
            links[f"sockets.target.wants/{name}"] = "../" + name
            starts.append(name)
    return {"units": rendered, "links": links, "starts": starts, "resource": unit_name}


def image_unit_digest(target):
    """Reads a regular immutable store member without following any aliases."""
    path = Path(target)
    parts = path.parts
    canonical_member = re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+(?:/[^/]+)*", target)
    if not canonical_member or str(path) != target or any(part in {".", ".."} for part in parts):
        raise ValueError("image service definition is not a canonical immutable store member")

    # Directory-relative NOFOLLOW opens authenticate the whole member path,
    # including intermediate directories, rather than just its final leaf.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            identity = os.fstat(source.fileno())
            if not stat.S_ISREG(identity.st_mode) or identity.st_mode & 0o222:
                raise ValueError("image service definition is not an immutable regular file")
            contents = source.read(2 * 1024 * 1024 + 1)
            if len(contents) > 2 * 1024 * 1024:
                raise ValueError("image service definition exceeds the bounded unit size")
            return digest(contents)
    finally:
        os.close(directory)


class Handler(ConfigurationHandler):
    """Reconciles systemd state using the shared resource ownership namespace."""

    def __init__(self, invocation, systemctl, unit_directory, state_directory):
        super().__init__(invocation, state_directory)
        self.systemctl = systemctl
        self.unit_directory = Path(unit_directory)

    def save(self, value):
        value = dict(value)
        if value.get("kind") == "service":
            names = set(value.get("units", {})) | set(value.get("links", {}))
            names.update(value.get("previous_units", {}))
            names.update(value.get("previous_links", {}))
            value["owned_paths"] = sorted(str(self.unit_directory / name) for name in names)
        super().save(value)

    def image_custody(self, desired, action):
        """Authenticates projected aliases before adopting their /etc entries."""
        receipt = self.receipt or {}
        custody = dict(receipt.get("image_units", {}))
        owned_names = set(receipt.get("units", {})) | set(receipt.get("previous_units", {}))
        eligible = self.value.get("bootstrap", False) or self.value.get("activation_owner", "ability") != "ability"
        if action == "remove" or self.invocation.get("action") == "remove":
            eligible = False
        for name, expected in desired.items():
            path = self.unit_directory / name
            if not path.is_symlink() or name in custody:
                continue
            if name in owned_names:
                raise ValueError("owned service definition was replaced by an external link")
            if not eligible:
                raise ValueError("service definition has no authenticated image projection")
            target = os.readlink(path)
            actual = image_unit_digest(target)
            if actual != expected:
                raise ValueError("image service definition conflicts with authenticated rendered content")
            custody[name] = {"target": target, "digest": actual}
        return custody

    def unit_digest(self, name, custody):
        """Checks an owned regular leaf or its exact pending image alias."""
        path = self.unit_directory / name
        if path.is_symlink():
            original = custody.get(name)
            if original is None or os.readlink(path) != original["target"]:
                raise ValueError("service definition link changed outside its owning effect")
            if image_unit_digest(original["target"]) != original["digest"]:
                raise ValueError("image service definition changed outside its retained custody")
            return original["digest"]
        return read_digest(path)

    def manager(self, *arguments, check=True):
        result = subprocess.run([self.systemctl, *arguments], check=False, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError("service manager operation failed: " + result.stderr[:4096])
        return result

    def concurrency_check(self):
        concurrency = self.value.get("concurrency")
        if not concurrency or not self.state_directory.exists():
            return
        for receipt_path in self.state_directory.glob("*.json"):
            if receipt_path == self.receipt_path:
                continue
            receipt = json.loads(receipt_path.read_text())
            if receipt.get("concurrency") == concurrency["group"]:
                observed = self.manager("show", receipt["resource"], "--property=ActiveState", "--value", check=False)
                if observed.returncode != 0 or observed.stdout.strip() in {"active", "activating", "reloading", "deactivating"}:
                    raise ValueError("another service is active in this exclusive concurrency group")

    def execution_evidence(self, unit_name):
        observed = self.manager("show", unit_name, "--property=ActiveState,Result,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic", check=False)
        if observed.returncode:
            return None
        fields = dict(line.split("=", 1) for line in observed.stdout.splitlines() if "=" in line)
        return fields

    def service(self, action):
        group = (self.value.get("resources") or {}).get("resource_group")
        identity = self.invocation["effect"]["identity"]
        if group and (len(identity) < 4 or not group.startswith("aos-pkg-" + identity[-4] + "-")):
            raise ValueError("service resource group must be a descendant of its owning package")
        realization = realize_service(self.value)
        unit_name = realization["resource"]
        result = {"resource": unit_name, "path": str(self.unit_directory / unit_name)}
        desired = {name: digest(text.encode()) for name, text in realization["units"].items()}
        prior_units = dict((self.receipt or {}).get("previous_units", {}), **(self.receipt or {}).get("units", {}))
        prior_links = dict((self.receipt or {}).get("previous_links", {}), **(self.receipt or {}).get("links", {}))
        owner = self.value.get("activation_owner", "ability")
        try:
            custody = self.image_custody(desired, action)
            for name in desired.keys() | prior_units.keys():
                self.unit_digest(name, custody)
        except (ValueError, OSError):
            if action == "observe":
                return {"status": "indeterminate"}
            raise
        expected = all(self.unit_digest(name, custody) == value for name, value in desired.items())
        expected = expected and self.links_match(realization["links"])
        if action == "observe" and self.invocation.get("action") == "remove":
            if self.receipt is None:
                absent = all(not (self.unit_directory / name).exists() and not (self.unit_directory / name).is_symlink() for name in desired)
                return {"status": "absent" if absent else "indeterminate"}
            if self.receipt.get("removing") and self.receipt.get("dispatching"):
                # A failed stop may have run arbitrary package commands. File
                # identity alone cannot authorize another lifecycle invocation.
                return {"status": "indeterminate"}
            if any(self.unit_digest(name, custody) not in {None, value} for name, value in prior_units.items()):
                return {"status": "indeterminate"}
            if not self.links_safe(prior_links):
                return {"status": "indeterminate"}
            absent = all(not (self.unit_directory / name).exists() and not (self.unit_directory / name).is_symlink() for name in prior_units)
            absent = absent and all(not (self.unit_directory / name).is_symlink() for name in prior_links)
            if absent:
                self.finish_remove()
                return {"status": "absent"}
            return {"status": "retry-safe"}
        if action == "observe":
            if self.receipt and self.receipt.get("pending") and self.receipt.get("dispatching"):
                if not expected or self.receipt["revision"] != self.invocation["revision"]:
                    return {"status": "indeterminate"}
                evidence = self.execution_evidence(unit_name)
                started = int((evidence or {}).get("ExecMainStartTimestampMonotonic", "0"))
                prior_start = int(self.receipt.get("prior_start", "0"))
                exited = int((evidence or {}).get("ExecMainExitTimestampMonotonic", "0"))
                if evidence and started > prior_start and evidence.get("Result") == "success" and (evidence.get("ActiveState") == "active" or exited >= started):
                    # Unit retirement may still be pending after dispatch. Reconcile
                    # it before acknowledging an otherwise successful execution.
                    if self.receipt.get("previous_units") or self.receipt.get("previous_links"):
                        return {"status": "indeterminate"}
                    self.save(dict(self.receipt, pending=False, dispatching=False))
                    return {"status": "current", "outputs": result}
                return {"status": "indeterminate"}
            if expected and self.receipt and not self.receipt.get("pending") and self.receipt["revision"] == self.invocation["revision"]:
                if owner == "ability" and self.value["auto_start"] and self.value["enabled"]:
                    state = self.manager("show", unit_name, "--property=ActiveState", "--value", check=False)
                    if state.returncode != 0 or state.stdout.strip() not in {"active", "reloading"}:
                        if self.value["lifecycle"]["execution_model"] != "oneshot":
                            return {"status": "retry-safe"}
                return {"status": "current", "outputs": result}
            safe = all(self.unit_digest(name, custody) in {None, value, prior_units.get(name), (self.receipt or {}).get("previous_units", {}).get(name)} for name, value in desired.items())
            safe = safe and self.links_safe(dict(prior_links, **realization["links"]))
            if not self.receipt and all(not (self.unit_directory / name).exists() for name in desired):
                return {"status": "absent"}
            return {"status": "retry-safe" if safe else "indeterminate"}
        if action == "remove":
            if not self.receipt:
                if all(not (self.unit_directory / name).exists() for name in desired):
                    return {}
                raise ValueError("service removal has no ownership receipt")
            for name, value in prior_units.items():
                if self.unit_digest(name, custody) not in {None, value}:
                    raise ValueError("service definition changed outside its owning effect")
            if not self.links_safe(prior_links):
                raise ValueError("service installation link changed outside its owning effect")
            for guard in self.value["lifecycle"].get("removal_guard", []):
                executable = guard["executable"]
                checked = subprocess.run([absolute(executable["path"]), *executable["arguments"]], capture_output=True, text=True, check=False)
                if checked.returncode and not guard["ignore_failure"]:
                    raise ValueError("service removal guard rejected retirement: " + checked.stderr[:4096])
            if self.receipt.get("owner") == "ability":
                self.save(dict(self.receipt, removing=True, dispatching=True))
                self.manager("stop", *self.receipt.get("starts", []), *self.receipt.get("units", {}))
                self.save(dict(self.receipt, dispatching=False))
            self.remove_links(prior_links)
            for name in prior_units:
                durable_unlink(self.unit_directory / name)
            self.manager("daemon-reload")
            return self.finish_remove()
        for name, value in desired.items():
            if self.unit_digest(name, custody) not in {None, value, prior_units.get(name), (self.receipt or {}).get("previous_units", {}).get(name)}:
                raise ValueError("service definition conflicts with external configuration")
        if not self.links_safe(prior_links):
            raise ValueError("service installation link changed outside its owning effect")
        new_links = {name: target for name, target in realization["links"].items() if name not in prior_links}
        if not self.links_safe(new_links):
            raise ValueError("service installation link conflicts with external configuration")
        self.concurrency_check()
        if self.value.get("concurrency"):
            lock_directory = Path("/run/aos-native-service-locks")
            lock_directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            lock_path = lock_directory / (digest(self.value["concurrency"]["group"].encode()) + ".lock")
            descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o666)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("service concurrency lock is not a regular file")
                os.fchmod(descriptor, 0o666)
            finally:
                os.close(descriptor)
        self.claim_paths([str(self.unit_directory / name) for name in set(desired) | set(realization["links"])])
        receipt = {"kind": "service", "units": desired, "links": realization["links"], "resource": unit_name, "starts": realization["starts"], "owner": owner, "pending": True, "previous_units": prior_units, "previous_links": prior_links, "image_units": custody, "concurrency": (self.value.get("concurrency") or {}).get("group")}
        old_resource = (self.receipt or {}).get("resource")
        self.save(receipt)
        for name, text in realization["units"].items():
            # Adopt the mutable /etc entry as a regular owned file. Pending
            # custody authenticates a projected alias only until this conversion.
            durable_write(self.unit_directory / name, text.encode())
        self.remove_links({name: target for name, target in prior_links.items() if realization["links"].get(name) != target})
        self.install_links(realization["links"])
        self.manager("daemon-reload")
        if old_resource and old_resource != unit_name and owner == "ability":
            self.manager("stop", old_resource)
        if owner == "ability" and not self.value["enabled"]:
            # Disabling keeps owned definitions and surviving worker identities.
            # Retirement guards apply only when removing the package's effect.
            self.manager("stop", *self.receipt.get("starts", []), *realization["units"])
        if owner == "ability" and self.value["enabled"] and self.value["auto_start"]:
            if realization["starts"]:
                self.manager("start", *realization["starts"])
            change = self.value["lifecycle"]["configuration_change_action"]
            update = self.invocation.get("previous") is not None
            operation = "reload-or-restart" if update and change == "reload" else "restart" if update and change == "restart" else "start"
            evidence = self.execution_evidence(unit_name)
            receipt.update(dispatching=True, prior_start=(evidence or {}).get("ExecMainStartTimestampMonotonic", "0"))
            self.save(receipt)
            self.manager(operation, unit_name)
        for name in prior_units.keys() - desired.keys():
            if self.unit_digest(name, custody) == prior_units[name]:
                durable_unlink(self.unit_directory / name)
        self.save(dict(receipt, pending=False, dispatching=False, previous_units={}, previous_links={}, image_units={}))
        return result

    def links_match(self, links):
        return all((self.unit_directory / name).is_symlink() and os.readlink(self.unit_directory / name) == target for name, target in links.items())

    def links_safe(self, links):
        for name, target in links.items():
            path = self.unit_directory / name
            if path.is_symlink():
                if os.readlink(path) != target:
                    return False
            elif path.exists():
                return False
        return True

    def install_links(self, links):
        for name, target in links.items():
            path = self.unit_directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                if os.readlink(path) != target:
                    raise ValueError("service installation link conflicts with external configuration")
            elif path.exists():
                raise ValueError("service installation link destination already exists")
            else:
                path.symlink_to(target)
                synchronize_directory(path.parent)

    def remove_links(self, links):
        for name, target in links.items():
            path = self.unit_directory / name
            if path.is_symlink() and os.readlink(path) == target:
                durable_unlink(path)
            elif path.exists() or path.is_symlink():
                raise ValueError("service installation link changed outside its owning effect")

    def device(self, action):
        path = absolute(self.value["path"])
        if action == "remove":
            return {}
        kind = self.value.get("kind", "character")
        predicates = {"character": stat.S_ISCHR, "block": stat.S_ISBLK}
        if kind not in predicates:
            raise ValueError("unsupported device node kind")
        exists = Path(path).exists() and predicates[kind](os.stat(path).st_mode)
        if action == "observe":
            return {"status": "current", "outputs": {"resource": path}} if exists else {"status": "retry-safe"}
        if not exists:
            raise ValueError("required device node is absent or has the wrong kind")
        return {"resource": path}


def render_services(services, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    identities = set()
    for name, value in services.items():
        if not value.get("enable", value.get("enabled", False)):
            continue
        value = dict(value, instance=name, service=value.get("service", name))
        realization = realize_service(value)
        if identities.intersection(realization["units"]):
            raise ValueError("service manager identities collide")
        identities.update(realization["units"])
        for unit_name, contents in realization["units"].items():
            durable_write(directory / unit_name, contents.encode())
        for link, target in realization["links"].items():
            path = directory / link
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() and os.readlink(path) == target:
                continue
            path.symlink_to(target)


def main():
    global TRUE_EXECUTABLE, FLOCK_EXECUTABLE, MAC_CONDITION_EXECUTABLE
    parser = argparse.ArgumentParser()
    parser.add_argument("--systemctl")
    parser.add_argument("--true-executable")
    parser.add_argument("--flock-executable")
    parser.add_argument("--mac-condition-executable")
    parser.add_argument("--unit-directory", default="/etc/systemd/system")
    parser.add_argument("--state-directory", default="/var/lib/aos/native-service-effects")
    parser.add_argument("action", choices=["apply", "remove", "observe", "render", "check-mac"])
    parser.add_argument("--output-dir")
    parser.add_argument("--negated", action="store_true")
    args = parser.parse_args()
    TRUE_EXECUTABLE = args.true_executable
    FLOCK_EXECUTABLE = args.flock_executable
    MAC_CONDITION_EXECUTABLE = args.mac_condition_executable
    if args.action == "check-mac":
        try:
            enforcing = Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
        except FileNotFoundError:
            enforcing = False
        # ExecCondition's exit 1 skips activation without marking the unit failed.
        sys.exit(0 if enforcing != args.negated else 1)
    document = read_invocation()
    if args.action == "render":
        if not args.output_dir:
            raise ValueError("build rendering requires an output directory")
        render_services(document, args.output_dir)
        return
    if not args.systemctl:
        raise ValueError("native service manager executable must be pinned")
    identity = document["effect"]["identity"]
    ability, operation = identity[-3:-1]
    def dispatch(state_directory):
        handler = Handler(document, args.systemctl, args.unit_directory, state_directory)
        operations = {("serviceManagement", "realize"): handler.service, ("device", "present"): handler.device}
        return operations[(ability, operation)](args.action)

    result = locked_dispatch(args.state_directory, dispatch)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("native service handler: " + str(error), file=sys.stderr)
        sys.exit(1)
