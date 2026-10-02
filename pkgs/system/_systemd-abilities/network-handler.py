"""Renders and converges native network policy with exact file ownership receipts.

The image renderer and runtime handler share the same networkd/resolved lowering.
Receipts retain both sides of an interrupted update before any managed file changes.
"""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

LIMIT = 1048576
STATE = Path("/var/lib/aos/network")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def value(text):
    require(isinstance(text, str) and text and not any(ord(c) < 32 for c in text), "invalid networkd value")
    require(not any(c in text for c in '\\"%'), "ambiguous networkd value")
    return '"' + text + '"'


def link_name(name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name), "invalid network link name")
    return name


def selector(match):
    kind = match["kind"]
    if kind == "ethernet":
        pattern = match.get("value", "")
        require(isinstance(pattern, str), "invalid Ethernet name pattern")
        if pattern:
            require(
                len(pattern) <= 15 and re.fullmatch(r"[A-Za-z0-9_.:-]+\*?", pattern),
                "invalid Ethernet name pattern",
            )
        return ("Name=" + value(pattern) + "\n" if pattern else "") + "Type=ether\n"
    if kind == "name":
        return "Name=" + value(link_name(match["value"])) + "\n"
    require(kind == "mac" and re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", match["value"]), "invalid MAC selector")
    return "MACAddress=" + match["value"] + "\n"


def addressing(policy):
    text = "DHCP=" + ("yes" if policy["dhcp"] else "no") + "\n"
    for address in policy["addresses"]:
        ipaddress.ip_interface(address)
        text += "Address=" + value(address) + "\n"
    if policy.get("gateway"):
        ipaddress.ip_address(policy["gateway"])
        text += "Gateway=" + value(policy["gateway"]) + "\n"
    for address in policy["dns"]:
        ipaddress.ip_address(address)
        text += "DNS=" + value(address) + "\n"
    link_local = policy.get("link_local", "ipv6")
    require(link_local in ("no", "ipv4", "ipv6", "yes"), "invalid link-local policy")
    text += "LinkLocalAddressing=" + link_local + "\n"
    dhcp_options = []
    for field, directive in (("dhcp_use_dns", "UseDNS"), ("dhcp_use_ntp", "UseNTP")):
        configured = policy.get(field)
        if configured is not None:
            require(type(configured) is bool, "invalid DHCPv4 boolean policy")
            dhcp_options.append(directive + "=" + ("yes" if configured else "no"))
    domains = policy.get("dhcp_use_domains")
    if domains is not None:
        require(domains in ("yes", "no", "route"), "invalid DHCPv4 domain policy")
        dhcp_options.append("UseDomains=" + domains)
    if dhcp_options:
        text += "\n[DHCPv4]\n" + "\n".join(dhcp_options) + "\n"
    if policy.get("ipv4_link_local_route", False):
        text += "\n[Route]\nDestination=169.254.0.0/16\nScope=link\n"
    return text


def render(policy):
    require(policy["authority"] in ("image", "operator"), "invalid policy authority")
    links = policy["links"]
    require(len(links) <= 1024, "too many managed links")
    names = [link["name"] for link in links]
    require(len(set(names)) == len(names), "duplicate managed link identity")
    files = {}
    parents = {}

    def parent(match, setting, child):
        identity = json.dumps(match, sort_keys=True, separators=(",", ":"))
        entry = parents.setdefault(identity, [match, []])
        entry[1].append(setting + "=" + value(child) + "\n")

    mtu = policy.get("mtu", 0)
    require(type(mtu) is int and 0 <= mtu <= 65535, "invalid MTU")
    link_settings = "[Link]\nMTUBytes=" + str(mtu) + "\n\n" if mtu else ""
    for link in sorted(links, key=lambda item: item["name"]):
        name = link["name"]
        kind = link["kind"]
        require(isinstance(name, str) and name and not any(ord(c) < 32 for c in name), "invalid link identity")
        basename = "10-aos-" + hashlib.sha256(name.encode()).hexdigest()[:24]
        if kind == "ethernet":
            match = link["selector"]
            require(match is not None, "physical link lacks selector")
        else:
            link_name(name)
            match = {"kind": "name", "value": name}
            netdev = "[NetDev]\nName=" + value(name) + "\nKind=" + kind + "\n"
            if kind == "vlan":
                require(type(link["id"]) is int and 1 <= link["id"] <= 4094, "invalid VLAN id")
                netdev += "\n[VLAN]\nId=" + str(link["id"]) + "\n"
                require(link["parent"] is not None, "VLAN lacks parent")
                parent(link["parent"], "VLAN", name)
            else:
                require(kind == "bond" and link["mode"] in ("balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"), "invalid bond mode")
                require(link["members"], "bond lacks members")
                netdev += "\n[Bond]\nMode=" + link["mode"] + "\n"
                for member in link["members"]:
                    parent(member, "Bond", name)
            files["etc/systemd/network/" + basename + ".netdev"] = netdev
        files["etc/systemd/network/" + basename + ".network"] = "[Match]\n" + selector(match) + "\n" + link_settings + "[Network]\n" + addressing(link["addressing"])

    # Attach virtual links in the matching physical definition. A separate
    # earlier .network file would shadow its address/DHCP policy in networkd.
    for identity, (match, attachments) in sorted(parents.items()):
        matching = [link for link in links if link["kind"] == "ethernet" and link["selector"] == match]
        if matching:
            basename = "10-aos-" + hashlib.sha256(matching[0]["name"].encode()).hexdigest()[:24]
            path = "etc/systemd/network/" + basename + ".network"
            text = files[path]
            # Attachment directives belong to Network, before DHCP/Route sections.
            sections = [
                position for marker in ("\n[DHCPv4]", "\n[Route]")
                if (position := text.find(marker)) >= 0
            ]
            split = min(sections) if sections else -1
            if split < 0:
                files[path] += "".join(sorted(attachments))
            else:
                files[path] = text[:split] + "\n" + "".join(sorted(attachments)) + text[split:]
        else:
            basename = "05-aos-parent-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
            files["etc/systemd/network/" + basename + ".network"] = "[Match]\n" + selector(match) + "\n" + link_settings + "[Network]\nDHCP=no\n" + "".join(sorted(attachments))
    resolver = policy["resolver"]
    require(resolver["dnssec"] in ("yes", "no", "allow-downgrade"), "invalid DNSSEC policy")
    if resolver["enabled"]:
        for address in resolver["nameservers"]:
            ipaddress.ip_address(address)
        text = "[Resolve]\nDNS=" + " ".join(value(address) for address in resolver["nameservers"]) + "\n"
        text += "Domains=" + " ".join(value(domain) for domain in resolver["search"]) + "\nDNSSEC=" + resolver["dnssec"] + "\n"
        files["etc/systemd/resolved.conf.d/50-aos-native.conf"] = text
    elif resolver["nameservers"] or resolver["search"]:
        text = "".join("nameserver " + str(ipaddress.ip_address(address)) + "\n" for address in resolver["nameservers"])
        if resolver["search"]:
            require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", domain) for domain in resolver["search"]), "invalid resolver search domain")
            text += "search " + " ".join(resolver["search"]) + "\n"
        files["etc/resolv.conf"] = text
    return files


def safe_path(path):
    require(path.is_absolute() and ".." not in path.parts, "resource path is not absolute")
    for ancestor in [path, *path.parents]:
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(metadata.st_mode), "resource path contains symlink")
        if ancestor != path:
            require(stat.S_ISDIR(metadata.st_mode), "resource ancestor is not a directory")


def read(path):
    safe_path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "managed path is not a regular file")
        content = stream.read(LIMIT + 1)
    require(len(content) <= LIMIT, "managed resource exceeds limit")
    return content.decode()


def write(path, content, mode=0o644):
    safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".aos-network-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    require(result.returncode == 0, "network manager command failed: " + result.stderr[:4096])


def units(args, resolved):
    files = {}
    names = ["systemd-networkd.service", "systemd-networkd.socket", "systemd-networkd-wait-online.service"]
    if resolved:
        names.append("systemd-resolved.service")
    for name in names:
        source = Path(args.unit_directory) / name
        require(str(source).startswith("/nix/store/"), "manager unit source is not immutable")
        content = source.read_text()
        require(len(content.encode()) <= LIMIT, "manager unit is oversized")
        files["etc/systemd/system/" + name] = content
    return files


def link_at(path):
    safe_path(path.parent)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        return os.readlink(path)
    return None


def checked(receipt):
    current = receipt["desired"]["files"]
    previous = receipt.get("previous") or {}
    old = previous.get("files", {})
    links = receipt["desired"].get("symlinks", {})
    old_links = previous.get("symlinks", {})
    complete = True
    for path in current.keys() | old.keys() | links.keys() | old_links.keys():
        target = Path("/") / path
        link = link_at(target)
        if link is not None:
            require(link in (links.get(path), old_links.get(path)), "managed resolver link changed outside its receipt")
            complete = complete and link == links.get(path)
        else:
            content = read(target)
            require(content is None or content in (current.get(path), old.get(path)), "managed network file changed outside its receipt")
            complete = complete and content == current.get(path) and path not in links
    return complete


def converge(args, invocation):
    operation = invocation["effect"]["identity"][-2]
    action = args.action
    if operation == "ready":
        if action == "remove":
            return {}
        if action == "observe" and invocation["action"] == "remove":
            return {"status": "absent"}
        policy = invocation["input"]
        try:
            if policy["required"]:
                command([args.systemctl, "is-active", "--quiet", "systemd-networkd.service"])
                if policy["scope"] == "address-configured":
                    flags = ["--" + family for family in policy["families"]]
                    command([args.wait_online, "--any", "--timeout=30", *flags])
            resource = "systemd-networkd.service" if policy["required"] else "sysinit.target"
            return {"status": "current", "outputs": {"resource": resource}} if action == "observe" else {"resource": resource}
        except (ValueError, subprocess.TimeoutExpired):
            if action == "observe":
                return {"status": "retry-safe"}
            raise
    require(operation in ("configure", "bootstrap"), "unsupported network operation")
    policy = invocation["input"]
    bootstrap = operation == "bootstrap"
    if bootstrap:
        configuration = policy["configuration"]
        if configuration is None:
            if action == "observe" and invocation["action"] == "remove":
                return {"status": "absent"}
            if action == "remove":
                return {}
            result = {"resource": "systemd-network-bootstrap-empty"}
            return {"status": "current", "outputs": result} if action == "observe" else result
        policy = {"authority": "operator", "links": [{"name": "metadata-bootstrap", "kind": "ethernet", "selector": configuration["selector"], "addressing": {"dhcp": False, "addresses": configuration["addresses"], "gateway": configuration.get("gateway"), "dns": configuration["dns"]}}], "resolver": {"enabled": False, "nameservers": [], "search": [], "dnssec": "no"}}

    desired = {"files": render(policy), "resolved": policy["resolver"]["enabled"], "revision": invocation["revision"]}
    if bootstrap:
        desired["files"] = {path.replace("/10-aos-", "/01-aos-bootstrap-"): content for path, content in desired["files"].items()}
    else:
        desired["files"].update(units(args, desired["resolved"]))
    desired["symlinks"] = {"etc/resolv.conf": "/run/systemd/resolve/stub-resolv.conf"} if desired["resolved"] else {}
    safe_path(STATE)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(STATE.stat().st_uid == 0 and not STATE.stat().st_mode & 0o077, "network state directory is not private root state")
    lock = os.open(STATE / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        receipt_path = STATE / (hashlib.sha256(invocation["id"].encode()).hexdigest() + ".json")
        previous_text = read(receipt_path)
        receipt = json.loads(previous_text) if previous_text else None
        if receipt:
            require(receipt["owner"] == invocation["id"], "network receipt owner mismatch")
            complete = checked(receipt)
        else:
            # The verified image may have seeded exactly the same policy.
            # Adoption cannot replace a differing administrator-owned file.
            for path, content in desired["files"].items():
                require(read(Path("/") / path) in (None, content), "unowned network resource exists")
            for path, target in desired["symlinks"].items():
                actual = link_at(Path("/") / path)
                require(actual == target or (actual is None and read(Path("/") / path) is None), "unowned resolver path exists")
            complete = False
        if action == "observe":
            if receipt is None and invocation["action"] == "remove":
                return {"status": "absent"}
            if receipt and complete and receipt["complete"] and receipt["desired"] == desired and invocation["action"] == "apply":
                command([args.systemctl, "is-active", "--quiet", "systemd-networkd.service"])
                if desired["resolved"]:
                    command([args.systemctl, "is-active", "--quiet", "systemd-resolved.service"])
                return {"status": "current", "outputs": {"resource": "systemd-networkd.service"}}
            return {"status": "retry-safe"}
        if action == "remove":
            if receipt:
                if not bootstrap:
                    command([args.systemctl, "stop", "systemd-networkd.service", "systemd-networkd.socket"])
                if receipt["desired"]["resolved"] or (receipt.get("previous") or {}).get("resolved"):
                    command([args.systemctl, "stop", "systemd-resolved.service"])
                paths = receipt["desired"]["files"].keys() | (receipt.get("previous") or {}).get("files", {}).keys()
                paths |= receipt["desired"].get("symlinks", {}).keys() | (receipt.get("previous") or {}).get("symlinks", {}).keys()
                for path in paths:
                    target = Path("/") / path
                    if link_at(target) is not None or read(target) is not None:
                        target.unlink()
                command([args.systemctl, "daemon-reload"])
                if bootstrap:
                    command([args.systemctl, "reload-or-restart", "systemd-networkd.service"])
                receipt_path.unlink()
            return {}
        if receipt and receipt["desired"] != desired:
            require(receipt["complete"] and receipt.get("previous") is None, "finish interrupted networking update before changing policy")
            receipt = {"owner": invocation["id"], "desired": desired, "previous": receipt["desired"], "complete": False}
        if receipt is None:
            receipt = {"owner": invocation["id"], "desired": desired, "previous": None, "complete": False}
        write(receipt_path, json.dumps(receipt, sort_keys=True), 0o600)
        old = receipt.get("previous") or {}
        if old.get("resolved") and not desired["resolved"]:
            command([args.systemctl, "stop", "systemd-resolved.service"])
        for path in old.get("symlinks", {}):
            target = Path("/") / path
            if link_at(target) is not None and old["symlinks"][path] != desired["symlinks"].get(path):
                target.unlink()
        for path in old.get("files", {}).keys() - desired["files"].keys():
            target = Path("/") / path
            if read(target) is not None:
                target.unlink()
        for path, content in desired["files"].items():
            write(Path("/") / path, content)
        for path, link in desired["symlinks"].items():
            target = Path("/") / path
            if link_at(target) is None:
                safe_path(target)
                require(read(target) is None, "resolver link destination was replaced")
                os.symlink(link, target)
        command([args.systemctl, "daemon-reload"])
        if not bootstrap:
            command([args.systemctl, "start", "systemd-networkd.socket"])
        command([args.systemctl, "reload-or-restart", "systemd-networkd.service"])
        if desired["resolved"]:
            command([args.systemctl, "restart", "systemd-resolved.service"])
        receipt["previous"] = None
        receipt["complete"] = True
        write(receipt_path, json.dumps(receipt, sort_keys=True), 0o600)
        return {"resource": "systemd-networkd.service"}
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--systemctl")
    parser.add_argument("--wait-online")
    parser.add_argument("--unit-directory")
    parser.add_argument("action", choices=["apply", "remove", "observe", "render-network"])
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "network invocation exceeds byte limit")
        data = json.loads(raw)
        if args.action == "render-network":
            require(args.output_dir is not None, "renderer requires output directory")
            for path, content in render(data).items():
                write(Path(args.output_dir).absolute() / path, content)
            return
        require(set(data) == {"id", "effect", "input", "revision", "action", "previous"}, "invalid native invocation fields")
        require(args.action == "observe" or args.action == data["action"], "action differs from invocation")
        require(re.fullmatch(r"[0-9a-f]{64}", data["revision"]), "invalid native revision")
        require(data["effect"]["identity"][-3] == "network", "invalid network effect identity")
        result = converge(args, data)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        if args.action == "observe":
            print(json.dumps({"status": "indeterminate"}))
            return
        print("aos-network-handler: " + str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
